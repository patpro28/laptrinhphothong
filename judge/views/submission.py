import json
from collections import namedtuple
from itertools import groupby
from operator import attrgetter

from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.cache import cache
from django.core.exceptions import (ImproperlyConfigured, ObjectDoesNotExist,
                                    PermissionDenied)
from django.db.models import Max, Min, Prefetch, Q
from django.http import (Http404, HttpResponse, HttpResponseBadRequest,
                         HttpResponseRedirect, JsonResponse)
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.html import escape, format_html
from django.utils.safestring import mark_safe
from django.utils.translation import gettext as _
from django.utils.translation import gettext_lazy
from django.views.decorators.http import require_POST
from django.views.generic import DetailView, ListView

from judge.highlight_code import highlight_code
from judge.models import (Language, Problem, ProblemTranslation, Profile,
                          Submission)
from judge.utils.infinite_paginator import InfinitePaginationMixin
from judge.utils.problem_data import get_problem_testcases_data
from judge.utils.problems import (get_result_data, user_completed_ids,
                                  user_editable_ids)
from judge.utils.raw_sql import join_sql_subquery, use_straight_join
from judge.utils.views import DiggPaginatorMixin, TitleMixin


def submission_related(queryset):
    return queryset.select_related('user', 'problem', 'language') \
        .only('id', 'user__user__username', 'user__display_rank', 'user__rating', 'problem__name',
              'problem__code', 'problem__is_public', 'language__short_name', 'language__key', 'date', 'time', 'memory',
              'points', 'result', 'status', 'case_points', 'case_total', 'current_testcase',
              'locked_after', 'problem__submission_source_visibility_mode')


class SubmissionMixin(object):
    model = Submission
    context_object_name = 'submission'
    pk_url_kwarg = 'submission'


class SubmissionDetailBase(LoginRequiredMixin, TitleMixin, SubmissionMixin, DetailView):
    def get_object(self, queryset=None):
        submission = super(SubmissionDetailBase, self).get_object(queryset)
        if not submission.can_see_detail(self.request.user):
            raise PermissionDenied()
        return submission

    def get_title(self):
        submission = self.object
        return _('Submission of %(problem)s by %(user)s') % {
            'problem': submission.problem.translated_name(self.request.LANGUAGE_CODE),
            'user': submission.user.username,
        }

    def get_content_title(self):
        submission = self.object
        return mark_safe(escape(_('Submission of %(problem)s by %(user)s')) % {
            'problem': format_html('<a href="{0}" class="text-blue-500">{1}</a>',
                                   reverse('problem_detail', args=[submission.problem.code]),
                                   submission.problem.translated_name(self.request.LANGUAGE_CODE)),
            'user': format_html('<a href="{0}" class="text-blue-500">{1}</a>',
                                reverse('user_page', args=[submission.user.username]),
                                submission.user.username),
        })


class SubmissionSource(SubmissionDetailBase):
    template_name = 'submission/source.html'

    def get_queryset(self):
        return super().get_queryset().select_related('source')

    def get_context_data(self, **kwargs):
        context = super(SubmissionSource, self).get_context_data(**kwargs)
        submission = self.object
        context['raw_source'] = submission.source.source.rstrip('\n')
        context['highlighted_source'] = highlight_code(submission.source.source, submission.language.pygments)
        return context


def make_batch(batch, cases):
    result = {'id': batch, 'cases': cases}
    if batch:
        result['points'] = min(map(attrgetter('points'), cases))
        result['total'] = max(map(attrgetter('total'), cases))
    return result


TestCase = namedtuple('TestCase', 'id status batch num_combined')


def get_statuses(batch, cases):
    cases = [TestCase(id=case.id, status=case.status, batch=batch, num_combined=1) for case in cases]
    if batch:
        # Get the first non-AC case if it exists.
        return [next((case for case in cases if case.status != 'AC'), cases[0])]
    else:
        return cases


def combine_statuses(status_cases, submission):
    ret = []
    # If the submission is not graded and the final case is a batch,
    # we don't actually know if it is completed or not, so just remove it.
    if not submission.is_graded and len(status_cases) > 0 and status_cases[-1].batch is not None:
        status_cases.pop()

    for key, group in groupby(status_cases, key=attrgetter('status')):
        group = list(group)
        if len(group) > 10:
            # Grab the first case's id so the user can jump to that case, and combine the rest.
            ret.append(TestCase(id=group[0].id, status=key, batch=None, num_combined=len(group)))
        else:
            ret.extend(group)
    return ret


def group_test_cases(cases):
    result = []
    status = []
    buf = []
    max_execution_time = 0.0
    last = None
    for case in cases:
        if case.time:
            max_execution_time = max(max_execution_time, case.time)
        if case.batch != last and buf:
            result.append(make_batch(last, buf))
            status.extend(get_statuses(last, buf))
            buf = []
        buf.append(case)
        last = case.batch
    if buf:
        result.append(make_batch(last, buf))
        status.extend(get_statuses(last, buf))
    return result, status, max_execution_time


class SubmissionStatus(SubmissionDetailBase):
    template_name = 'submission/status.html'

    def get_context_data(self, **kwargs):
        context = super(SubmissionStatus, self).get_context_data(**kwargs)
        submission = self.object
        # context['last_msg'] = event.last()

        context['batches'], statuses, context['max_execution_time'] = group_test_cases(submission.test_cases.all())
        context['statuses'] = combine_statuses(statuses, submission)
        context['can_view_test'] = submission.problem.is_testcase_accessible_by(self.request.user)
        if context['can_view_test']:
            context['cases_data'] = get_problem_testcases_data(submission.problem)
        else:
            context['cases_data'] = {}

        context['time_limit'] = submission.problem.time_limit
        try:
            lang_limit = submission.problem.language_limits.get(language=submission.language)
        except ObjectDoesNotExist:
            pass
        else:
            context['time_limit'] = lang_limit.time_limit
        return context


class SubmissionTestCaseQuery(SubmissionStatus):
    template_name = 'submission/status-testcases.html'

    def get(self, request, *args, **kwargs):
        if 'id' not in request.GET or not request.GET['id'].isdigit():
            return HttpResponseBadRequest()
        self.kwargs[self.pk_url_kwarg] = kwargs[self.pk_url_kwarg] = int(request.GET['id'])
        return super(SubmissionTestCaseQuery, self).get(request, *args, **kwargs)


class SubmissionSourceRaw(SubmissionSource):
    def get(self, request, *args, **kwargs):
        if not (self.request.user.is_authenticated and (self.request.user.is_superuser or self.request.user.is_staff)):
            return Http404()
        submission = self.get_object()
        return HttpResponse(submission.source.source, content_type='text/plain')


@require_POST
def abort_submission(request, submission):
    submission = get_object_or_404(Submission, id=int(submission))
    if (not request.user.has_perm('judge.abort_any_submission') and
       (submission.rejudged_date is not None or request.user != submission.user)):
        raise PermissionDenied()
    submission.abort()
    return HttpResponseRedirect(reverse('submission_status', args=(submission.id,)))


def filter_submissions_by_visible_problems(queryset, user):
    problems = Problem.get_visible_problems(user).distinct().values_list('id', flat=True)
    queryset = queryset.filter(problem_id__in=problems)


class SubmissionsListBase(DiggPaginatorMixin, TitleMixin, ListView):
    model = Submission
    paginate_by = 50
    show_problem = True
    title = gettext_lazy('All submissions')
    content_title = gettext_lazy('All submissions')
    tab = 'all_submissions_list'
    template_name = 'submission/list.html'
    context_object_name = 'submissions'
    first_page_href = None

    def get_result_data(self):
        result = self._get_result_data()
        for category in result['categories']:
            category['name'] = _(category['name'])
        return result

    def _get_result_data(self, queryset=None):
        if queryset is None:
            queryset = self.get_queryset()
        return get_result_data(queryset.order_by())

    def access_check(self, request):
        pass

    def _get_queryset(self):
        queryset = Submission.objects.all()
        use_straight_join(queryset)
        queryset = submission_related(queryset.order_by('-id'))
        if self.show_problem:
            queryset = queryset.prefetch_related(Prefetch('problem__translations',
                                                          queryset=ProblemTranslation.objects.filter(
                                                              language=self.request.LANGUAGE_CODE), to_attr='_trans'))

        if self.selected_languages:
            languages = Language.objects.filter(key__in=self.selected_languages)
            queryset = queryset.filter(language__in=languages)
        if self.selected_statuses and len(self.selected_statuses) > 0:
            queryset = queryset.filter(result__in=self.selected_statuses)

        return queryset

    def get_queryset(self):
        queryset = self._get_queryset()
        filter_submissions_by_visible_problems(queryset, self.request.user)

        return queryset

    def get_my_submissions_page(self):
        return None

    def get_all_submissions_page(self):
        return reverse('all_submissions')

    def get_searchable_status_codes(self):
        hidden_codes = ['SC']
        if not self.request.user.is_superuser and not self.request.user.is_staff:
            hidden_codes += ['IE']
        return [(key, value) for key, value in Submission.RESULT if key not in hidden_codes]

    def get_context_data(self, **kwargs):
        context = super(SubmissionsListBase, self).get_context_data(**kwargs)
        authenticated = self.request.user.is_authenticated
        context['dynamic_update'] = False
        context['show_problem'] = self.show_problem
        context['completed_problem_ids'] = user_completed_ids(self.request.profile) if authenticated else []
        context['editable_problem_ids'] = user_editable_ids(self.request.user) if authenticated else []

        context['all_languages'] = Language.objects.all().values_list('key', 'name')
        context['selected_languages'] = self.selected_languages

        context['all_statuses'] = self.get_searchable_status_codes()
        context['selected_statuses'] = self.selected_statuses

        context['results_json'] = mark_safe(json.dumps(self.get_result_data()))
        context['results_colors_json'] = mark_safe(json.dumps(settings.DMOJ_STATS_SUBMISSION_RESULT_COLORS))

        context['page_suffix'] = suffix = ('?' + self.request.GET.urlencode()) if self.request.GET else ''
        context['first_page_href'] = (self.first_page_href or '.') + suffix
        context['my_submissions_link'] = self.get_my_submissions_page()
        context['all_submissions_link'] = self.get_all_submissions_page()
        context['tab'] = self.tab
        return context

    def get(self, request, *args, **kwargs):
        check = self.access_check(request)
        if check is not None:
            return check
        if 'language' in request.GET and request.GET.get('language'):
            self.selected_languages = set(request.GET.get('language').split(','))
        else:
            self.selected_languages = None
        if 'status' in request.GET and request.GET.get('status'):
            self.selected_statuses = set(request.GET.get('status').split(','))
        else:
            self.selected_statuses = None
        if 'results' in request.GET:
            return JsonResponse(self.get_result_data())

        return super(SubmissionsListBase, self).get(request, *args, **kwargs)


class UserMixin(object):
    def get(self, request, *args, **kwargs):
        if 'user' not in kwargs:
            raise ImproperlyConfigured('Must pass a user')
        self.profile = get_object_or_404(Profile, user__username=kwargs['user'])
        self.username = kwargs['user']
        return super(UserMixin, self).get(request, *args, **kwargs)


class ConditionalUserTabMixin(object):
    @cached_property
    def is_own(self):
        return self.request.user.is_authenticated and self.request.user == self.profile

    def get_context_data(self, **kwargs):
        context = super(ConditionalUserTabMixin, self).get_context_data(**kwargs)
        if self.is_own:
            context['tab'] = 'my_submissions_tab'
        else:
            context['tab'] = 'user_submissions_tab'
            context['tab_username'] = self.profile.username
        return context


class AllUserSubmissions(ConditionalUserTabMixin, UserMixin, SubmissionsListBase):
    def get_queryset(self):
        return super(AllUserSubmissions, self).get_queryset().filter(user_id=self.profile.id)

    def get_title(self):
        if self.is_own:
            return _('All my submissions')
        return _('All submissions by %s') % self.username

    def get_content_title(self):
        if self.is_own:
            return format_html('All my submissions')
        return format_html('All submissions by <a href="{1}">{0}</a>', self.username,
                           reverse('user_page', args=[self.username]))

    def get_my_submissions_page(self):
        if self.request.user.is_authenticated:
            return reverse('all_user_submissions', kwargs={'user': self.request.user.username})

    def get_context_data(self, **kwargs):
        context = super(AllUserSubmissions, self).get_context_data(**kwargs)
        context['dynamic_update'] = context['page_obj'].number == 1
        context['dynamic_user_id'] = self.profile.id
        # context['last_msg'] = event.last()
        return context


class ProblemSubmissionsBase(SubmissionsListBase):
    show_problem = False
    dynamic_update = True
    check_contest_in_access_check = True

    def get_queryset(self):
        return super(ProblemSubmissionsBase, self)._get_queryset().filter(problem_id=self.problem.id)

    def get_title(self):
        return _('All submissions for %s') % self.problem_name

    def get_content_title(self):
        return format_html('All submissions for <a href="{1}">{0}</a>', self.problem_name,
                           reverse('problem_detail', args=[self.problem.code]))

    def access_check_contest(self, request):
        if self.in_contest and not self.contest.can_see_own_scoreboard(request.user):
            raise Http404()

    def access_check(self, request):
        if not self.problem.is_accessible_by(request.user):
            raise Http404()

    def get(self, request, *args, **kwargs):
        if 'problem' not in kwargs:
            raise ImproperlyConfigured(_('Must pass a problem'))
        self.problem = get_object_or_404(Problem, code=kwargs['problem'])
        self.problem_name = self.problem.translated_name(self.request.LANGUAGE_CODE)
        return super(ProblemSubmissionsBase, self).get(request, *args, **kwargs)

    def get_all_submissions_page(self):
        return reverse('chronological_submissions', kwargs={'problem': self.problem.code})

    def get_context_data(self, **kwargs):
        context = super(ProblemSubmissionsBase, self).get_context_data(**kwargs)
        if self.dynamic_update:
            context['dynamic_update'] = context['page_obj'].number == 1
            context['dynamic_problem_id'] = self.problem.id
            # context['last_msg'] = event.last()
        context['best_submissions_link'] = reverse('ranked_submissions', kwargs={'problem': self.problem.code})
        return context


class ProblemSubmissions(ProblemSubmissionsBase):
    def get_my_submissions_page(self):
        if self.request.user.is_authenticated:
            return reverse('user_submissions', kwargs={'problem': self.problem.code,
                                                       'user': self.request.user.username})


class UserProblemSubmissions(ConditionalUserTabMixin, UserMixin, ProblemSubmissions):
    check_contest_in_access_check = False

    def access_check(self, request):
        super(UserProblemSubmissions, self).access_check(request)

    def get_queryset(self):
        return super(UserProblemSubmissions, self).get_queryset().filter(user_id=self.profile.id)

    def get_title(self):
        if self.is_own:
            return _("My submissions for %(problem)s") % {'problem': self.problem_name}
        return _("%(user)s's submissions for %(problem)s") % {'user': self.username, 'problem': self.problem_name}

    def get_content_title(self):
        if self.request.user.is_authenticated and self.request.profile == self.profile:
            return format_html('''My submissions for <a href="{3}">{2}</a>''',
                               self.username, reverse('user_page', args=[self.username]),
                               self.problem_name, reverse('problem_detail', args=[self.problem.code]))
        return format_html('''<a href="{1}">{0}</a>'s submissions for <a href="{3}">{2}</a>''',
                           self.username, reverse('user_page', args=[self.username]),
                           self.problem_name, reverse('problem_detail', args=[self.problem.code]))

    def get_context_data(self, **kwargs):
        context = super(UserProblemSubmissions, self).get_context_data(**kwargs)
        context['dynamic_user_id'] = self.profile.id
        return context


def single_submission(request):
    request.no_profile_update = True
    if 'id' not in request.GET or not request.GET['id'].isdigit():
        return HttpResponseBadRequest()
    try:
        show_problem = int(request.GET.get('show_problem', '1'))
    except ValueError:
        return HttpResponseBadRequest()

    authenticated = request.user.is_authenticated
    submission = get_object_or_404(submission_related(Submission.objects.all()), id=int(request.GET['id']))
    if not submission.problem.is_accessible_by(request.user):
        raise Http404()

    return render(request, 'submission/row.html', {
        'submission': submission,
        'completed_problem_ids': user_completed_ids(request.profile) if authenticated else [],
        'editable_problem_ids': user_editable_ids(request.user) if authenticated else [],
        'show_problem': show_problem,
        'problem_name': show_problem and submission.problem.translated_name(request.LANGUAGE_CODE),
        'profile_id': request.user.id if authenticated else 0,
    })


class AllSubmissions(InfinitePaginationMixin, SubmissionsListBase):
    stats_update_interval = 3600

    @property
    def use_infinite_pagination(self):
        return True

    def get_my_submissions_page(self):
        if self.request.user.is_authenticated:
            return reverse('all_user_submissions', kwargs={'user': self.request.user.username})

    def get_context_data(self, **kwargs):
        context = super(AllSubmissions, self).get_context_data(**kwargs)
        context['dynamic_update'] = context['page_obj'].number == 1
        # context['last_msg'] = event.last()
        context['stats_update_interval'] = self.stats_update_interval
        return context

    def _get_result_data(self, queryset=None):
        if queryset is not None or self.selected_languages or self.selected_statuses:
            return super(AllSubmissions, self)._get_result_data(queryset)

        key = 'global_submission_result_data'
        result = cache.get(key)
        if result:
            return result
        result = super(AllSubmissions, self)._get_result_data(Submission.objects.all())
        cache.set(key, result, self.stats_update_interval)
        return result


class RankedSubmissions(ProblemSubmissions):
    tab = 'best_submissions_list'
    dynamic_update = False

    def get_queryset(self):
        params = [self.problem.id]
        contest_join = ''
        points = 'sub.points'
        constraint = ''

        if self.selected_languages:
            lang_ids = Language.objects.filter(key__in=self.selected_languages).values_list('id', flat=True)
            if lang_ids:
                constraint += f' AND sub.language_id IN ({", ".join(["%s"] * len(lang_ids))})'
                params.extend(lang_ids)
            self.selected_languages = set()

        queryset = super(RankedSubmissions, self).get_queryset().filter(user__is_unlisted=False)

        join_sql_subquery(
            queryset,
            subquery='''
                SELECT sub.id AS id
                FROM (
                    SELECT sub.user_id AS uid, MAX(sub.points) AS points
                    FROM judge_submission AS sub {contest_join}
                    WHERE sub.problem_id = %s AND {points} > 0 {constraint}
                    GROUP BY sub.user_id
                ) AS highscore STRAIGHT_JOIN (
                    SELECT sub.user_id AS uid, sub.points, MIN(sub.time) as time
                    FROM judge_submission AS sub {contest_join}
                    WHERE sub.problem_id = %s AND {points} > 0 {constraint}
                    GROUP BY sub.user_id, {points}
                ) AS fastest ON (highscore.uid = fastest.uid AND highscore.points = fastest.points)
                    STRAIGHT_JOIN judge_submission AS sub
                        ON (sub.user_id = fastest.uid AND sub.time = fastest.time) {contest_join}
                WHERE sub.problem_id = %s AND {points} > 0 {constraint}
                GROUP BY sub.user_id
            '''.format(points=points, contest_join=contest_join, constraint=constraint),
            params=params * 3, alias='best_subs', join_fields=[('id', 'id')],
        )

        return queryset.order_by('-points', 'time')

    def get_title(self):
        return _('Best solutions for %s') % self.problem_name

    def get_content_title(self):
        return format_html(_('Best solutions for <a class="content_title" href="{1}">{0}</a>'), self.problem_name,
                           reverse('problem_detail', args=[self.problem.code]))

    def _get_result_data(self, queryset=None):
        if queryset is None:
            queryset = super(RankedSubmissions, self).get_queryset()
        return get_result_data(queryset.order_by())
