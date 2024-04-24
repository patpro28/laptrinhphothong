"""
This file was generated with the customdashboard management command and
contains the class for the main dashboard.

To activate your index dashboard add the following to your settings.py::
    GRAPPELLI_INDEX_DASHBOARD = 'tmath.dashboard.CustomIndexDashboard'
"""

from django.utils.translation import gettext_lazy as _
from django.urls import reverse

from grappelli.dashboard import modules, Dashboard
from grappelli.dashboard.utils import get_admin_site_name


class TmathDashboard(Dashboard):

    def __init__(self, **kwargs):
        Dashboard.__init__(self, **kwargs)

        self.children.append(modules.AppList(
            title=_('Hot models'),
            column=1,
            collapsible=False,
            models=(
                'judge.models.problem.Problem',
                'judge.models.contest.Contest',
                'judge.models.contest.SampleContest',
                'judge.models.profile.Profile',
                'judge.models.interface.Log',
            )
        ))

        self.children.append(modules.AppList(
            title=_('Authentication'),
            column=1,
            collapsible=True,
            css_classes=['grp-closed', ],
            models=(
                "django.contrib.auth.models.Group",
                'judge.models.profile.Profile',
                'django.contrib.admin.models.LogEntry',
            )
        ))

        self.children.append(modules.AppList(
            title=_('Organizations'),
            column=1,
            collapsible=True,
            css_classes=['grp-closed', ],
            models=(
                'judge.models.profile.*',
            ),
            exclude=('judge.models.profile.Profile',)
        ))

        self.children.append(modules.AppList(
            title=_('Problems'),
            column=1,
            collapsible=True,
            css_classes=['grp-closed', ],
            models=(
                'judge.models.problem.*',
                'judge.models.problem_data.PublicSolution'
            )
        ))

        self.children.append(modules.AppList(
            title=_('Contests'),
            column=1,
            collapsible=True,
            css_classes=['grp-closed', ],
            models=(
                'judge.models.contest.*',
            )
        ))

        self.children.append(modules.AppList(
            title=_('Submissions'),
            column=1,
            collapsible=True,
            css_classes=['grp-closed', ],
            models=(
                'judge.models.submission.*',
                'judge.models.runtime.*'
            )
        ))

        self.children.append(modules.AppList(
            title=_('Blogs'),
            column=1,
            collapsible=True,
            css_classes=['grp-closed', ],
            models=(
                'judge.models.comment.*',
                'judge.models.ticket.*',
                'judge.models.interface.BlogPost',
            )
        ))

        self.children.append(modules.AppList(
            title=_('Settings'),
            column=1,
            collapsible=True,
            css_classes=['grp-closed', ],
            models=(
                'django.contrib.flatpages.*',
                'django.contrib.sites.*',
                'judge.models.interface.NavigationBar',
            )
        ))

        self.children.append(modules.RecentActions(
            title=_('Recent actions'),
            column=2,
            collapsible=False,
            limit=20,
        ))

        # self.children.append(modules.Feed(
        #     title=_('Latest Django News'),
        #     feed_url='http://www.djangoproject.com/rss/weblog/',
        #     column=3,
        #     limit=20,
        # ))

    # def init_with_context(self, context):
        # site_name = get_admin_site_name(context)

        # # append a group for "Administration" & "Applications"
        # self.children.append(modules.Group(
        #     _('Group: Administration & Applications'),
        #     column=1,
        #     collapsible=True,
        #     children = [
        #         modules.AppList(
        #             _('Administration'),
        #             column=1,
        #             collapsible=False,
        #             models=('django.contrib.*',),
        #         ),
        #         modules.AppList(
        #             _('Applications'),
        #             column=1,
        #             css_classes=('collapse closed',),
        #             exclude=('django.contrib.*',),
        #         )
        #     ]
        # ))

        # # append an app list module for "Applications"
        # self.children.append(modules.AppList(
        #     _('AppList: Applications'),
        #     collapsible=True,
        #     column=1,
        #     css_classes=('collapse closed',),
        #     exclude=('django.contrib.*',),
        # ))

        # # append an app list module for "Administration"
        # self.children.append(modules.ModelList(
        #     _('ModelList: Administration'),
        #     column=1,
        #     collapsible=False,
        #     models=('django.contrib.*',),
        # ))

        # # append another link list module for "support".
        # self.children.append(modules.LinkList(
        #     _('Media Management'),
        #     column=2,
        #     children=[
        #         {
        #             'title': _('FileBrowser'),
        #             'url': '/admin/filebrowser/browse/',
        #             'external': False,
        #         },
        #     ]
        # ))

        # # append another link list module for "support".
        # self.children.append(modules.LinkList(
        #     _('Support'),
        #     column=2,
        #     children=[
        #         {
        #             'title': _('Django Documentation'),
        #             'url': 'http://docs.djangoproject.com/',
        #             'external': True,
        #         },
        #         {
        #             'title': _('Grappelli Documentation'),
        #             'url': 'http://packages.python.org/django-grappelli/',
        #             'external': True,
        #         },
        #         {
        #             'title': _('Grappelli Google-Code'),
        #             'url': 'http://code.google.com/p/django-grappelli/',
        #             'external': True,
        #         },
        #     ]
        # ))

        # # append a feed module
        # self.children.append(modules.Feed(
        #     _('Latest Django News'),
        #     column=2,
        #     feed_url='http://www.djangoproject.com/rss/weblog/',
        #     limit=5
        # ))

        # # append a recent actions module
        # self.children.append(modules.RecentActions(
        #     _('Recent actions'),
        #     limit=5,
        #     collapsible=False,
        #     column=3,
        # ))
