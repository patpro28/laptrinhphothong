from django.contrib import admin
from django.contrib.admin.models import LogEntry
from django.contrib.flatpages.models import FlatPage

from judge.admin.comments import CommentAdmin
from judge.admin.interface import (BlogPostAdmin, FlatPageAdmin, LicenseAdmin,
                                   LogAdmin, LogEntryAdmin, NavigationBarAdmin)
from judge.admin.organization import (OrganizationAdmin,
                                      OrganizationRequestAdmin)
from judge.admin.problem import ProblemAdmin, PublicSolutionAdmin
from judge.admin.profile import ProfileAdmin
from judge.admin.runtime import JudgeAdmin, LanguageAdmin
from judge.admin.submission import SubmissionAdmin
from judge.admin.taxon import ProblemTypeAdmin
from judge.admin.ticket import TicketAdmin
from judge.admin.user import UserAdmin
from judge.models import (BlogPost, Comment, CommentLock, Judge, Language,
                          License, Log, MiscConfig, NavigationBar,
                          Organization, OrganizationRequest, Problem,
                          ProblemType, Profile, Submission, Ticket, User)
from judge.models.problem_data import PublicSolution

admin.site.register(BlogPost, BlogPostAdmin)
admin.site.register(Comment, CommentAdmin)
admin.site.register(CommentLock)
admin.site.unregister(FlatPage)
admin.site.register(FlatPage, FlatPageAdmin)
admin.site.register(Judge, JudgeAdmin)
admin.site.register(Language, LanguageAdmin)
admin.site.register(License, LicenseAdmin)
admin.site.register(LogEntry, LogEntryAdmin)
admin.site.register(Log, LogAdmin)
admin.site.register(MiscConfig)
admin.site.register(NavigationBar, NavigationBarAdmin)
admin.site.register(Organization, OrganizationAdmin)
admin.site.register(OrganizationRequest, OrganizationRequestAdmin)
admin.site.register(Problem, ProblemAdmin)
admin.site.register(ProblemType, ProblemTypeAdmin)
admin.site.register(Profile, ProfileAdmin)
admin.site.register(Submission, SubmissionAdmin)
admin.site.register(Ticket, TicketAdmin)
admin.site.register(PublicSolution, PublicSolutionAdmin)
admin.site.register(User, UserAdmin)
