import csv
import itertools
import json
import os
from datetime import datetime
from operator import attrgetter, itemgetter

import pytz as timezone
from django import forms
from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView
from django.contrib.auth.views import LogoutView as BaseLogoutView
from django.contrib.auth.views import PasswordChangeView, redirect_to_login
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import Count, Max, Min
from django.db.models.fields import DateField
from django.db.models.functions import Cast, ExtractYear
from django.http import (Http404, HttpResponse, HttpResponseRedirect,
                         JsonResponse)
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.utils.formats import date_format
from django.utils.functional import cached_property
from django.utils.safestring import mark_safe
from django.utils.translation import gettext as _
from django.utils.translation import gettext_lazy
from django.views.decorators.http import require_POST
from django.views.generic import (DetailView, FormView, ListView, TemplateView,
                                  UpdateView, View)
from reversion import revisions
from unidecode import unidecode

from judge.forms import (CreateManyUserForm, CustomAuthenticationForm,
                         DownloadDataForm, ProfileForm)
from judge.models import Language, Profile, Rating, Submission
from judge.models.profile import Organization
from judge.performance_points import get_pp_breakdown
from judge.ratings import rating_class, rating_progress
from judge.tasks import prepare_user_data
from judge.utils.celery import task_status_by_id, task_status_url_by_id
from judge.utils.problems import contest_completed_ids, user_completed_ids
from judge.utils.ranker import ranker
from judge.utils.unicode import utf8text
from judge.utils.views import (DiggPaginatorMixin, QueryStringSortMixin,
                               TitleMixin, add_file_response, generic_message)

from .contests import ContestRanking

__all__ = ['UserPage', 'UserAboutPage', 'UserProblemsPage', 'UserDownloadData', 'UserPrepareData',
           'users', 'edit_profile']


def remap_keys(iterable, mapping):
    return [dict((mapping.get(k, k), v) for k, v in item.items()) for item in iterable]


class UserMixin(object):
    model = Profile
    slug_field = 'user__username'
    slug_url_kwarg = 'user'
    context_object_name = 'user'

    def render_to_response(self, context, **response_kwargs):
        return super(UserMixin, self).render_to_response(context, **response_kwargs)


class UserPage(TitleMixin, UserMixin, DetailView):
    template_name = 'user/user-base.html'

    def get_object(self, queryset=None):
        if self.kwargs.get(self.slug_url_kwarg, None) is None:
            return self.request.user
        return super(UserPage, self).get_object(queryset)

    def dispatch(self, request, *args, **kwargs):
        if self.kwargs.get(self.slug_url_kwarg, None) is None:
            if not self.request.user.is_authenticated:
                return redirect_to_login(self.request.get_full_path())
        try:
            return super(UserPage, self).dispatch(request, *args, **kwargs)
        except Http404:
            return generic_message(request, _('No such user'), _('No user handle "%s".') %
                                   self.kwargs.get(self.slug_url_kwarg, None))

    def get_title(self):
        return (_('My account') if self.request.user == self.object.user else
                _('User %s') % self.object.username)

    # TODO: the same code exists in problem.py, maybe move to problems.py?
    @cached_property
    def profile(self):
        if not self.request.user.is_authenticated:
            return None
        return self.request.profile

    @cached_property
    def in_contest(self):
        return self.profile is not None and self.profile.current_contest is not None

    def get_completed_problems(self):
        if self.in_contest:
            return contest_completed_ids(self.profile.current_contest)
        else:
            return user_completed_ids(self.profile) if self.profile is not None else ()

    def get_context_data(self, **kwargs):
        context = super(UserPage, self).get_context_data(**kwargs)

        context['hide_solved'] = int(self.hide_solved)
        context['authored'] = self.object.authored_problems.filter(is_public=True, is_organization_private=False) \
                                  .order_by('code')
        rating = self.object.ratings.order_by('-contest__end_time')[:1]
        context['rating'] = rating[0] if rating else None

        context['rank'] = Profile.objects.filter(
            is_unlisted=False, performance_points__gt=self.object.performance_points,
        ).count() + 1

        if rating:
            context['rating_rank'] = Profile.objects.filter(
                is_unlisted=False, rating__gt=self.object.rating,
            ).count() + 1
            context['rated_users'] = Profile.objects.filter(is_unlisted=False, rating__isnull=False).count()
        context.update(self.object.ratings.aggregate(min_rating=Min('rating'), max_rating=Max('rating'),
                                                     contests=Count('contest')))
        return context

    def get(self, request, *args, **kwargs):
        self.hide_solved = request.GET.get('hide_solved') == '1' if 'hide_solved' in request.GET else False
        return super(UserPage, self).get(request, *args, **kwargs)


class CustomLoginView(LoginView):
    template_name = 'registration/login.html'
    extra_context = {'title': gettext_lazy('Login')}
    authentication_form = CustomAuthenticationForm
    redirect_authenticated_user = True

    # def form_valid(self, form):
    #     password = form.cleaned_data['password']
    #     validator = PwnedPasswordsValidator()
    #     try:
    #         validator.validate(password)
    #     except ValidationError:
    #         self.request.session['password_pwned'] = True
    #     else:
    #         self.request.session['password_pwned'] = False
    #     return super().form_valid(form)


class CustomPasswordChangeView(PasswordChangeView):
    template_name = 'registration/password_change_form.html'

    def form_valid(self, form):
        self.request.session['password_pwned'] = False
        return super().form_valid(form)


EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class UserAboutPage(UserPage):
    template_name = 'user/user-about.html'

    def get_context_data(self, **kwargs):
        context = super(UserAboutPage, self).get_context_data(**kwargs)
        ratings = context['ratings'] = self.object.ratings.order_by('-contest__end_time').select_related('contest') \
            .defer('contest__description')

        context['rating_data'] = mark_safe(json.dumps([{
            'label': rating.contest.name,
            'rating': rating.rating,
            'ranking': rating.rank,
            'link': '%s#!%s' % (reverse('contest_ranking', args=(rating.contest.key,)), self.object.username),
            'timestamp': (rating.contest.end_time - EPOCH).total_seconds() * 1000,
            'date': date_format(rating.contest.end_time, _('M j, Y, G:i')),
            'class': rating_class(rating.rating),
            'height': '%.3fem' % rating_progress(rating.rating),
        } for rating in ratings]))

        if ratings:
            user_data = self.object.ratings.aggregate(Min('rating'), Max('rating'))
            global_data = Rating.objects.aggregate(Min('rating'), Max('rating'))
            min_ever, max_ever = global_data['rating__min'], global_data['rating__max']
            min_user, max_user = user_data['rating__min'], user_data['rating__max']
            delta = max_user - min_user
            ratio = (max_ever - max_user) / (max_ever - min_ever) if max_ever != min_ever else 1.0
            context['max_graph'] = max_user + ratio * delta
            context['min_graph'] = min_user + ratio * delta - delta

        submissions = (
            self.object.submission_set
            .annotate(date_only=Cast('date', DateField()))
            .values('date_only').annotate(cnt=Count('id'))
        )

        context['submission_data'] = mark_safe(json.dumps({
            date_counts['date_only'].isoformat(): date_counts['cnt'] for date_counts in submissions
        }))
        context['submission_metadata'] = mark_safe(json.dumps({
            'min_year': (
                self.object.submission_set
                .annotate(year_only=ExtractYear('date'))
                .aggregate(min_year=Min('year_only'))['min_year']
            ),
        }))
        return context


class UserProblemsPage(UserPage):
    template_name = 'user/user-problems.html'

    def get_context_data(self, **kwargs):
        context = super(UserProblemsPage, self).get_context_data(**kwargs)

        result = Submission.objects.filter(user=self.object, points__gt=0, problem__is_public=True,
                                           problem__is_organization_private=False) \
            .exclude(problem__in=self.get_completed_problems() if self.hide_solved else []) \
            .values('problem__id', 'problem__code', 'problem__name', 'problem__points', 'problem__group__full_name') \
            .distinct().annotate(points=Max('points')).order_by('problem__group__full_name', 'problem__code')

        def process_group(group, problems_iter):
            problems = list(problems_iter)
            points = sum(map(itemgetter('points'), problems))
            return {'name': group, 'problems': problems, 'points': points}

        context['best_submissions'] = [
            process_group(group, problems) for group, problems in itertools.groupby(
                remap_keys(result, {
                    'problem__code': 'code', 'problem__name': 'name', 'problem__points': 'total',
                    'problem__group__full_name': 'group',
                }), itemgetter('group'))
        ]
        breakdown, has_more = get_pp_breakdown(self.object, start=0, end=10)
        context['pp_breakdown'] = breakdown
        context['pp_has_more'] = has_more

        return context


class UserPerformancePointsAjax(UserProblemsPage):
    template_name = 'user/pp-table-body.html'

    def get_context_data(self, **kwargs):
        context = super(UserPerformancePointsAjax, self).get_context_data(**kwargs)
        try:
            start = int(self.request.GET.get('start', 0))
            end = int(self.request.GET.get('end', settings.DMOJ_PP_ENTRIES))
            if start < 0 or end < 0 or start > end:
                raise ValueError
        except ValueError:
            start, end = 0, 100
        breakdown, self.has_more = get_pp_breakdown(self.object, start=start, end=end)
        context['pp_breakdown'] = breakdown
        return context

    def get(self, request, *args, **kwargs):
        httpresp = super(UserPerformancePointsAjax, self).get(request, *args, **kwargs)
        httpresp.render()

        return JsonResponse({
            'results': utf8text(httpresp.content),
            'has_more': self.has_more,
        })


class UserDataMixin:
    @cached_property
    def data_path(self):
        return os.path.join(settings.DMOJ_USER_DATA_CACHE, '%s.zip' % self.request.user.id)

    def dispatch(self, request, *args, **kwargs):
        if not settings.DMOJ_USER_DATA_DOWNLOAD or self.request.user.mute:
            raise Http404()
        return super().dispatch(request, *args, **kwargs)


class UserPrepareData(LoginRequiredMixin, UserDataMixin, TitleMixin, FormView):
    template_name = 'user/prepare-data.html'
    form_class = DownloadDataForm

    @cached_property
    def _now(self):
        return timezone.now()

    @cached_property
    def can_prepare_data(self):
        return (
            self.request.user.data_last_downloaded is None or
            self.request.user.data_last_downloaded + settings.DMOJ_USER_DATA_DOWNLOAD_RATELIMIT < self._now or
            not os.path.exists(self.data_path)
        )

    @cached_property
    def data_cache_key(self):
        return 'celery_status_id:user_data_download_%s' % self.request.user.id

    @cached_property
    def in_progress_url(self):
        status_id = cache.get(self.data_cache_key)
        status = task_status_by_id(status_id).status if status_id else None
        return (
            self.build_task_url(status_id)
            if status in ('PENDING', 'PROGRESS', 'STARTED')
            else None
        )

    def build_task_url(self, status_id):
        return task_status_url_by_id(
            status_id, message=_('Preparing your data...'), redirect=reverse('user_prepare_data'),
        )

    def get_title(self):
        return _('Download your data')

    def form_valid(self, form):
        self.request.user.data_last_downloaded = self._now
        self.request.user.save()
        status = prepare_user_data.delay(self.request.user.id, json.dumps(form.cleaned_data))
        cache.set(self.data_cache_key, status.id)
        return HttpResponseRedirect(self.build_task_url(status.id))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['can_prepare_data'] = self.can_prepare_data
        context['can_download_data'] = os.path.exists(self.data_path)
        context['in_progress_url'] = self.in_progress_url
        context['ratelimit'] = settings.DMOJ_USER_DATA_DOWNLOAD_RATELIMIT

        if not self.can_prepare_data:
            context['time_until_can_prepare'] = (
                settings.DMOJ_USER_DATA_DOWNLOAD_RATELIMIT - (self._now - self.request.user.data_last_downloaded)
            )
        return context

    def post(self, request, *args, **kwargs):
        if not self.can_prepare_data or self.in_progress_url is not None:
            raise PermissionDenied()
        return super().post(request, *args, **kwargs)


class UserDownloadData(LoginRequiredMixin, UserDataMixin, View):
    def get(self, request, *args, **kwargs):
        if not os.path.exists(self.data_path):
            raise Http404()

        response = HttpResponse()

        if hasattr(settings, 'DMOJ_USER_DATA_INTERNAL'):
            url_path = '%s/%s.zip' % (settings.DMOJ_USER_DATA_INTERNAL, self.request.user.id)
        else:
            url_path = None
        add_file_response(request, response, url_path, self.data_path)

        response['Content-Type'] = 'application/zip'
        response['Content-Disposition'] = 'attachment; filename=%s-data.zip' % self.request.user.username
        return response


class EditProfile(LoginRequiredMixin, TitleMixin, UpdateView):
    template_name: str = 'user/edit-profile.html'
    form_class = ProfileForm
    context_object_name: str = 'profile'
    slug_field: str = 'user__username'
    slug_url_kwarg: str = 'user'
    model = Profile

    def get_title(self):
        return _('Edit %s profile') % self.object.username

    def form_valid(self, form) -> HttpResponse:
        with revisions.create_revision(atomic=True):
            self.object = form.save()
            revisions.set_user(self.request.user)
            revisions.set_comment(_('Updated on site'))
        
        return HttpResponseRedirect(self.request.path)

    def dispatch(self, request, *args, **kwargs):
        self.object = self.get_object()
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs) -> HttpResponse:
        if request.profile.mute:
            raise Http404()
        if request.profile != self.object and not request.user.is_superuser:
            raise Http404()
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tzmap = settings.TIMEZONE_MAP
        context['can_download_data'] = bool(settings.DMOJ_USER_DATA_DOWNLOAD)
        context['TIMEZONE_MAP'] = tzmap or 'http://momentjs.com/static/img/world.png'
        context['TIMEZONE_BG'] = settings.TIMEZONE_BG if tzmap else '#4E7CAD'
        return context


class UserList(QueryStringSortMixin, DiggPaginatorMixin, TitleMixin, ListView):
    model = Profile
    title = gettext_lazy('Leaderboard')
    context_object_name = 'users'
    template_name = 'user/list.html'
    paginate_by = 100
    all_sorts = frozenset(('points', 'problem_count', 'rating', 'performance_points'))
    default_desc = all_sorts
    default_sort = '-performance_points'

    def get_queryset(self):
        return (Profile.objects.filter(is_unlisted=False, user__is_active=True).order_by(self.order)
                .only('display_rank', 'user__username', 'points', 'rating', 'performance_points',
                      'problem_count'))

    def get_context_data(self, **kwargs):
        context = super(UserList, self).get_context_data(**kwargs)
        context['users'] = ranker(
            context['users'],
            key=attrgetter('performance_points', 'problem_count'),
            rank=self.paginate_by * (context['page_obj'].number - 1),
        )
        queryset = self.get_queryset()
        context['gold'] = queryset[0] if queryset.count() > 0 else None
        context['silver'] = queryset[1] if queryset.count() > 1 else None
        context['bronze'] = queryset[2] if queryset.count() > 2 else None
        context['first_page_href'] = '.'
        context.update(self.get_sort_context())
        context.update(self.get_sort_paginate_context())
        return context


user_list_view = UserList.as_view()


class FixedContestRanking(ContestRanking):
    contest = None

    def get_object(self, queryset=None):
        return self.contest


def users(request):
    if request.user.is_authenticated:
        participation = request.profile.current_contest
        if participation is not None:
            contest = participation.contest
            return FixedContestRanking.as_view(contest=contest)(request, contest=contest.key)
    return user_list_view(request)


def user_ranking_redirect(request):
    try:
        username = request.GET['handle']
    except KeyError:
        raise Http404()
    user = get_object_or_404(Profile, user__username=username)
    rank = Profile.objects.filter(is_unlisted=False, performance_points__gt=user.performance_points).count()
    rank += Profile.objects.filter(
        is_unlisted=False, performance_points__exact=user.performance_points, id__lt=user.id,
    ).count()
    page = rank // UserList.paginate_by
    return HttpResponseRedirect('%s%s#!%s' % (reverse('user_list'), '?page=%d' % (page + 1) if page else '', username))


class UserLogoutView(TitleMixin, BaseLogoutView):
    template_name = 'registration/logout.html'
    title = gettext_lazy('You have been successfully logged out.')

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return HttpResponseRedirect(reverse('auth_login'))
        return super().dispatch(request, *args, **kwargs)


class CreateCSVUserForm(forms.Form):
    organization = forms.ChoiceField(choices=(), label='Organization')
    csv_file = forms.FileField(label='CSV file')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['organization'].choices = Organization.objects.all().values_list('id', 'name')
        self.fields['organization'].widget.attrs['class'] = '''
                    block
                    w-full
                    mt-1
                    rounded-md
                    border-gray-300
                    shadow-sm
                    focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50
                  '''
        # self.fields['csv_file'].widget = FileInput()

    def clean_csv_file(self):
        csv_file = self.cleaned_data['csv_file']
        if not csv_file.name.endswith('.csv'):
            raise forms.ValidationError('File is not CSV type')
        return csv_file


class CreateCSVUser(TitleMixin, FormView):
    form_class = CreateCSVUserForm
    template_name: str = 'user/csvuserform.html'
    title = 'Create many user from csv'
    success_url = reverse_lazy('create_user_confirm')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['all_organization'] = Organization.objects.all().values_list('id', 'name')
        return context

    def get_username(self, fullname, index):
        names = unidecode(fullname).lower().split()
        n = len(names)
        name = ''.join(names[i][0] for i in range(n - 1))
        name = names[-1] + name
        return name + index

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_superuser:
            raise Http404()
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form: CreateCSVUserForm) -> HttpResponse:
        org_id = form.cleaned_data['organization']
        csv_file = form.cleaned_data['csv_file']
        decoded_file = csv_file.read().decode('utf-8-sig')
        csv_data = csv.DictReader(decoded_file.splitlines(), delimiter=';')
        print(csv_data.fieldnames)
        data_list = list(csv_data)
        for row in data_list:
            print(row.keys())
            username = self.get_username(row['fullname'], row['MSHV'])
            row['username'] = username
        context = {
            'data': data_list,
            'organization': org_id,
        }
        self.request.session['create_csv_user'] = context
        return super().form_valid(form)


class ConfirmCSVUserForm(forms.Form):
    mshv = forms.CharField(widget=forms.HiddenInput(), required=True)
    firstname = forms.CharField(label='First name', required=True)
    lastname = forms.CharField(label='Last name', required=True)
    username = forms.CharField(label='Username', required=True)
    # password = forms.CharField(label='Password', required=False)
    email = forms.EmailField(label='Email', required=False)
    organization = forms.ChoiceField(choices=(), label='Organization', required=False)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.fields['organization'].choices = Organization.objects.all().values_list('id', 'name')


class ConfirmCSVUser(TitleMixin, FormView):
    template_name: str = 'user/confirm_csv_user.html'
    # model = None
    title = 'Confirm create many user from csv'
    form_class = ConfirmCSVUserForm
    success_url = reverse_lazy('success_csv_user')

    def get_formset(self):
        formset_class = forms.formset_factory(self.form_class, extra=0)
        csv_data = self.request.session.get('create_csv_user', {}).get('data', [])
        org_id = self.request.session.get('create_csv_user', {}).get('organization', None)
        formset_data = [
            {
                'mshv': row['MSHV'],
                'firstname': row['firstname'],
                'lastname': row['lastname'],
                'username': row['username'],
                # 'password': '',
                'email': row['email'] if 'email' in row else '',
                'organization': org_id,
            } for row in csv_data
        ]
        if self.request.method == 'POST':
            return formset_class(self.request.POST)
        return formset_class(initial=formset_data)

    def get(self, request, *args, **kwargs):
        if not request.session.get('create_csv_user', None):
            return HttpResponseRedirect(reverse_lazy('create_csv_user'))
        formset = self.get_formset()
        return self.render_to_response(self.get_context_data(formset=formset))

    def post(self, request, *args, **kwargs):
        formset = self.get_formset()
        if formset.is_valid():
            return self.form_valid(formset)
        return self.form_invalid(formset)

    def form_valid(self, formset) -> HttpResponse:
        language = Language.get_default_language()
        update_list = []
        with transaction.atomic():
            for form in formset:
                index = form.cleaned_data['mshv']
                username = form.cleaned_data['username']
                password = None  # form.cleaned_data['password']
                firstname = form.cleaned_data['firstname']
                lastname = form.cleaned_data['lastname']
                if not password:
                    password = Profile.objects.make_random_password()
                if Profile.objects.filter(username=username).exists():
                    Profile.objects.filter(username=username).delete()
                new_user = Profile.objects.create_user(
                    username=username,
                    password=password,
                    language=language,
                    first_name=firstname,
                    last_name=lastname,
                )
                org_id = form.cleaned_data['organization']
                data = [
                    index,
                    firstname,
                    lastname,
                    username,
                    password,
                ]
                if org_id:
                    org: Organization = Organization.objects.get(id=org_id)
                    org.members.add(new_user)
                    data.append(org.name)
                update_list.append(data)
        del self.request.session['create_csv_user']
        self.request.session['update_list'] = update_list
        return super().form_valid(formset)


class SuccessCSVUser(TitleMixin, TemplateView):
    template_name: str = 'user/success_csv_user.html'
    title = 'Success create many user from csv'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['update_list'] = self.request.session.get('update_list', [])
        return context

    def get(self, request, *args, **kwargs) -> HttpResponse:
        if request.GET.get('download', '') == 'true':
            return self.download_data()
        return super().get(request, *args, **kwargs)

    def download_data(self):
        list = self.request.session.get('update_list', [])
        if not list:
            return Http404()
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="list_user.csv"'
        writer = csv.writer(response)
        writer.writerow(['MSHV', 'Firstname', 'Lastname', 'Username', 'Password', 'Organization'])
        for data in list:
            writer.writerow(data)
        return response



class CreateManyUser(TitleMixin, FormView):
    form_class = CreateManyUserForm
    template_name: str = 'user/manyuserform.html'
    title = 'Create many user'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['all_organization'] = Organization.objects.all().values_list('id', 'name')
        return context

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_superuser:
            raise Http404()
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form: CreateManyUserForm) -> HttpResponse:
        prefix = form.cleaned_data['prefix_user']
        start = form.cleaned_data['start_id']
        end = form.cleaned_data['end_id']
        org_id = form.cleaned_data['organization']
        info = form.files.get('info', None)
        if org_id:
            org: Organization = Organization.objects.get(id=org_id)
        response = HttpResponse(content_type='text/csv',)
        response['Content-Disposition'] = 'attachment; filename="%s_list_user.csv"' % prefix
        response.write(u'\ufeff'.encode('utf8'))
        writer = csv.writer(response)
        users = []
        print(info)
        with transaction.atomic():
            if info:
                writer.writerow(['Username', 'Password', 'Fullname', 'First name', 'Last name', 'School', 'Country'])
                csv_file = info.read().decode("utf-8")        
                csv_reader = csv_file.split('\n')
                for index, row in enumerate(csv.reader(csv_reader)):
                    # row = line.split(",")
                    # print(row)
                    if index == 0:
                        continue
                    str_id = str(index)
                    while (len(str_id) < 4):
                        str_id = '0' + str_id
                    username = prefix + str_id
                    if Profile.objects.filter(username=username).exists():
                        Profile.objects.filter(username=username).delete()
                    password = Profile.objects.make_random_password()
                    user = Profile(username=username, first_name=row[2], last_name=row[3])
                    user.set_password(password)
                    users.append(user)
                    writer.writerow([username, password, row[1], row[2], row[3], row[4], row[5]])
            else:
                writer.writerow(['Username', 'Password'])
                for id in range(start, end + 1):
                    str_id = str(id)
                    while len(str_id) < 4:
                        str_id = '0' + str_id
                    username = prefix + str_id
                    password = Profile.objects.make_random_password()
                    writer.writerow([username, password])
                    if Profile.objects.filter(username=username).exists():
                        Profile.objects.filter(username=username).delete()
                    user = Profile(username=username)
                    user.set_password(password)
                    users.append(user)
        objs = Profile.objects.bulk_create(users)
        if org_id:
            for user in objs:
                org.members.add(user)
        return response