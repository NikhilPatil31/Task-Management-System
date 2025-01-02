from django.db import models
from django.contrib.auth.models import AbstractUser, User
from django.utils.translation import gettext_lazy as _

# Create your models here.
# class User(AbstractUser):
#     email = models.EmailField(unique=True)
#     # choice = (
#     #     ("Admin","Admin"),
#     #     ("Manager","Manager"),
#     #     ("Members","Members")
#     # )
#     # role = models.CharField(max_length=10,choices=choice)
#     # team = models.ForeignKey(Team,on_delete=models.CASCADE, null=True, blank=True)

#     def __str__(self):
#         return self.username

class Team(models.Model):
    name = models.CharField(max_length=250)
    description = models.TextField()
    members = models.ManyToManyField(User,through='TeamMembers',related_name='teams')


    def __str__(self):
        return self.name
    
class TeamMembers(models.Model):
    class Role(models.TextChoices):
        ADMIN = 'admin', _('Admin')
        MANAGER = 'manager', _('Manager')
        MEMBER = 'member', _('Member')

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    team = models.ForeignKey(Team, related_name="team_members", on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices= Role.choices, default=Role.ADMIN)


class Task(models.Model):
    
    class Status(models.TextChoices):
        NOT_STARTED = 'not_started', _('Not Started')
        IN_PROGRESS = 'in_progress', _('In Progress')
        IN_REVIEW = 'in_review', _('In Review')
        REVIEWED = 'reviewed', _('Reviewed')
        COMPLETED = 'completed', _('Completed')

    class Priority(models.TextChoices):
        LOW = 'low', _('Low')
        MEDIUM = 'medium', _('Medium')
        HIGH = 'high', _('High')

    title = models.CharField(max_length=200)
    description = models.TextField()

    status = models.CharField(
        max_length=15,
        choices=Status.choices,
        default=Status.NOT_STARTED
    )
    priority = models.CharField(
        max_length=10,
        choices=Priority.choices,
        default=Priority.MEDIUM
    )

    deadline = models.DateTimeField()
    
    creation_Date = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    creator = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='created_tasks'
    )
    assignee = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='assigned_tasks',
        null=True,
        blank=True
    )
    reviewer = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='review_tasks',
        null=True,
        blank=True
    )
    team = models.ForeignKey(
        Team,
        on_delete=models.CASCADE,
        related_name='tasks'
    )

    def __str__(self):
        return f"{self.title} ({self.status})"
