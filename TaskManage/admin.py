from django.contrib import admin
from .models import Task,Team,TeamMembers

# Register your models here.
# @admin.register(User)
# class UserAdmin(admin.ModelAdmin):
#     list_display = ['id','username','email','password']

@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = ['id','title','description','status','priority','creation_Date','updated_at','deadline','creator','assignee', 'reviewer','team']

@admin.register(Team)
class TeamAdmin(admin.ModelAdmin):
    list_display = ['id','name','description']

@admin.register(TeamMembers)
class TeamMembersAdmin(admin.ModelAdmin):
    list_display = ['id','user','team','role']