from rest_framework import serializers
from .models import User, Team, Task, TeamMembers


class RegistrationSerializer(serializers.ModelSerializer):
    username = serializers.CharField()
    email = serializers.EmailField()
    # choice = (
    #     ("Admin","Admin"),
    #     ("Manager","Manager"),
    #     ("Members","Members")
    # )
    # role = serializers.ChoiceField(choices=choice)
    password = serializers.CharField()
    confirm_password = serializers.CharField()

    class Meta:
        model = User
        fields = ['username','email','password','confirm_password']

class LoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField()
    password = serializers.CharField()

    class Meta:
        model = User
        fields = ['username', 'password']

class UserSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email']

class TeamMembersSerializer(serializers.ModelSerializer):
    # user = UserSerializer()
    user = serializers.CharField(source="user.username")
    class Meta:
        model = TeamMembers
        fields = ['user', 'role']

class TeamSerializer(serializers.ModelSerializer):
    members = TeamMembersSerializer(many=True,source="team_members")

    class Meta:
        model = Team
        fields = ['id', 'name', 'description', 'members']


class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = [
            'id', 'title', 'description', 'status', 'priority', 
            'creation_Date','deadline', 
            'assignee', 'reviewer'
        ]


class AddRemoveTeamMembersSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    role = serializers.ChoiceField(choices=TeamMembers.Role, required = False)

class TaskUpdationSerializer(serializers.Serializer):
    task_id = serializers.IntegerField()
    # title = serializers.CharField(required = False)
    description = serializers.CharField(required = False)
    status = serializers.ChoiceField(choices=Task.Status, required = False)
    priority = serializers.ChoiceField(choices=Task.Priority, required = False)
    creator = serializers.IntegerField(required = False)
    assignee = serializers.IntegerField(required = False)

class TaskFilteringSerializer(serializers.Serializer):
    choice = serializers.CharField()
    filter = serializers.CharField(required = False)