from reversion import revisions

from judge.models.choices import (ACE_THEMES, EFFECTIVE_MATH_ENGINES,
                                  MATH_ENGINES_CHOICES, TIMEZONE)
from judge.models.comment import Comment, CommentLock, CommentVote
from judge.models.interface import (BlogPost, CourseModel, Log, MiscConfig,
                                    NavigationBar, validate_regex)
from judge.models.problem import (LanguageLimit, License, Problem,
                                  ProblemClarification, ProblemTranslation,
                                  ProblemType, Solution,
                                  SubmissionSourceAccess,
                                  TranslatedProblemQuerySet)
from judge.models.problem_data import (CHECKERS, ProblemData, ProblemTestCase,
                                       PublicSolution, problem_data_storage,
                                       problem_directory_file)
from judge.models.profile import (Organization, OrganizationRequest, Profile,
                                  User)
from judge.models.runtime import Judge, Language, RuntimeVersion
from judge.models.submission import (SUBMISSION_RESULT, Submission,
                                     SubmissionSource, SubmissionTestCase)
from judge.models.ticket import Ticket, TicketMessage

revisions.register(Language)
revisions.register(Profile, exclude=['points', 'last_access', 'ip', 'rating'])
revisions.register(Problem, follow=['language_limits'])
revisions.register(LanguageLimit)
revisions.register(Organization)
revisions.register(BlogPost)
revisions.register(Solution)
revisions.register(Judge, fields=['name', 'created', 'auth_key', 'description'])
revisions.register(Comment, fields=['author', 'time', 'page', 'score', 'body', 'hidden', 'parent'])
del revisions
