from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponse
from rest_framework.response import Response
from .models import User, Team, Task, TeamMembers
from .forms import RegistrationForm, LoginForm, TeamCreationForm
from .serializers import LoginSerializer, TeamSerializer, UserSerializer, TaskSerializer, RegistrationSerializer, TeamMembersSerializer, AddRemoveTeamMembersSerializer, TaskUpdationSerializer, TaskFilteringSerializer
# from rest_framework.authentication import authenticate
from django.contrib.auth import login, logout, authenticate
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from django.contrib.auth.decorators import login_required
# from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from drf_yasg.utils import swagger_auto_schema
from rest_framework.decorators import APIView
from rest_framework.renderers import JSONRenderer
from rest_framework import status
import json
from django.db.models import Q

# Create your views here.
class RegisterView(APIView):
    @swagger_auto_schema(tags=['Auth'],request_body=RegistrationSerializer)
    def post(self, request):
        data = request.data
        serializer = RegistrationSerializer(data=data)
        
        if serializer.is_valid():
            
            username = serializer.data.get('username',False)
            email = serializer.data.get('email',False)
            # role = serializer.data.get('role',False)
            password = serializer.data.get('password',False)
            confirm_password = serializer.data.get('confirm_password',False)

            user = authenticate(username=username, password = password)
            if user:
                return Response({
                    "status" : True,
                    "message" : "Username already exist please login or enter different username",
                    "data" : {} 
                })

            
            if password == confirm_password:
                user = User.objects.create_user(username = username, email=email, password = password)
                user.save()

                refresh = RefreshToken.for_user(user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                })        
        
        return Response({
            'status' : True,
            'message' : 'Something Wrong',
            'data' : serializer.errors
        })

class LoginViewAdmin(APIView):
    @swagger_auto_schema(tags=['Auth'],request_body=LoginSerializer)
    def post(self,request):
        data = request.data
        serializer = LoginSerializer(data= data)
        # Permission_classes = [IsAdminUser]

        if serializer.is_valid():
            username = serializer.data.get('username',False)
            password = serializer.data.get('password',False)

            user = authenticate(username=username, password = password)
            if user:
                if user.is_superuser:

                    teams = Team.objects.all()
                    print(teams)
                    serializer = TeamSerializer(teams, many= True)
                    print(serializer)
                    teamdata = JSONRenderer().render(serializer.data)
                    team_data = json.loads(teamdata)
                    
                    users = User.objects.filter(is_superuser=False)
                    serializer = UserSerializer(users, many=True)
                    userdata = JSONRenderer().render(serializer.data)
                    user_data = json.loads(userdata)

                    tasks = Task.objects.all()
                    serializer = TaskSerializer(tasks, many=True)
                    taskdata = JSONRenderer().render(serializer.data)
                    task_data = json.loads(taskdata)

                    return Response({
                        'status' : True,
                        'message' : 'You have an access.',
                        'Users' : user_data,
                        'Teams' : team_data,
                        'Tasks' : task_data
                    })
                
                else:
                    return Response({
                        'status' : True,
                        'message' : "You don't have an access for this url."
                    })
            
        
        return Response({
            'status' : True,
            'message' : 'Something Wrong',
            'data' : serializer.errors
        })
    
class LoginViewManager(APIView):
    @swagger_auto_schema(tags=['Auth'],request_body=LoginSerializer)
    def post(self,request):
        data = request.data
        serializer = LoginSerializer(data= data)

        if serializer.is_valid():
            username = serializer.data.get('username',False)
            password = serializer.data.get('password',False)

            user = authenticate(username=username, password = password)
            if user:
                if user.is_staff or user.is_superuser:

                    return Response({
                        'status' : True,
                        'message' : 'You have an access.',
                    })
                
                else:
                    return Response({
                        'status' : True,
                        'message' : "You don't have an access for this url."
                    })
            
            else:
                token = RefreshToken.for_user(user)
                return Response({
                        'refresh': str(token),
                        'access': str(token.access_token),
                    })
        
        return Response({
            'status' : True,
            'message' : 'Something Wrong',
            'data' : serializer.errors
        })
    
class LoginViewMembers(APIView):
    @swagger_auto_schema(tags=['Auth'],request_body=LoginSerializer)
    def post(self,request):
        data = request.data
        serializer = LoginSerializer(data= data)

        if serializer.is_valid():
            username = serializer.data.get('username',False)
            password = serializer.data.get('password',False)

            user = authenticate(username=username, password = password)
            if user:
                if user.is_staff or user.is_superuser or user.is_active:

                    token = RefreshToken.for_user(user)
                    tasks = Task.objects.filter(assignee = user.id)
                    serializer = TaskSerializer(tasks, many=True)
                    data = JSONRenderer().render(serializer.data)

                    teams = Team.objects.filter(members = user.id)
                    serializer = TeamSerializer(teams,many=True)
                    teamdata = JSONRenderer().render(serializer.data)
                    team_data = json.loads(teamdata)

                    return Response({
                        'status' : True,
                        'message' : 'You have an access.',
                        'Tasks' : team_data
                    })
                
                else:
                    return Response({
                        'status' : True,
                        'message' : "You don't have an access for this url."
                    })
            
            else:
                return Response({
                    'status' : True,
                    'message' : 'Username and password is invalid'
                })
                
        
        return Response({
            'status' : True,
            'message' : 'Something Wrong',
            'data' : serializer.errors
        })    


class CreateTeamView(APIView):
    @swagger_auto_schema(tags=['Team Management'],request_body=TeamSerializer)
    def post(self,request):
        
        try:
            team = Team.objects.get(name = request.data.get('name'))
            if team: 
                return Response({
                    "status" : True,
                    "message" : "Team already exists please try to create new team.",
                })
            
        except Team.DoesNotExist:
            # return Response({"error": "Team not found"}, status=status.HTTP_404_NOT_FOUND)

            serializer = TeamSerializer(data=request.data)
            
            print('#')
            if serializer.is_valid():
                print('#1')
                name = serializer.data.get('name')
                print('#2')
                description = serializer.data.get('description')

                print("1")
                team = Team.objects.create(name = name, description = description)

                members = serializer.data.get('members',[])
                if not members:
                    return Response({"error": "At least one member is required."})
                
                print(members)
                print("2")
                team_members_data = []
                for member in members:
                    user_id = member.get('user')
                    print(user_id)
                    role = member.get('role')

                    user = get_object_or_404(User, id=user_id)

                    print("3")
                    team_member = TeamMembers.objects.create(team=team, user=user, role=role)
                    # print(TeamMembersSerializer(team_member).data)
                    team_members_data.append(TeamMembersSerializer(team_member).data)

                team_data = TeamSerializer(team).data
                # print(team_data)
                # print("4")
                # print(team_members_data)
                team_data['members'] = team_members_data

                return Response(team_data)
                
            print("*")
            return Response({
                'status' : False,
                'message' : 'Something Wrong'
            })
        
class AddTeamMembers(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(tags=['Team Management'],request_body=AddRemoveTeamMembersSerializer)
    def post(self,request,team_id):
        try:
            team = Team.objects.get(id = team_id)
            user_role = TeamMembers.objects.filter(team = team, user = request.user).first()

            print(request.user)
            
            if user_role is None or user_role.role not in ['admin', 'manager']:
                return Response({"error": "You do not have permission to add members to this team."}, status=status.HTTP_403_FORBIDDEN)
        
        except Team.DoesNotExist:
            return Response({"error": "Team not found"}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = AddRemoveTeamMembersSerializer(data = request.data)

        if serializer.is_valid():
            user_id = serializer.validated_data["user_id"]
            role = serializer.validated_data["role"]

            user = get_object_or_404(User, id=user_id)

            if TeamMembers.objects.filter(user=user, team=team).exists():
                return Response({"error":"User is already exists in team"}, status=status.HTTP_400_BAD_REQUEST)
            
            TeamMembers.objects.create(team=team, user=user, role=role)

            return Response({"Message":"User added successfully"},status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    
class RemoveTeamMembers(APIView):
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(tags=['Team Management'])
    def post(self, request, team_id, user_id):
        try:
            team = Team.objects.get(id = team_id)
            user_role = TeamMembers.objects.filter(team=team, user=request.user).first()

            if user_role is None or user_role.role not in ['admin', 'manager']:
                return Response({"error": "You do not have permission to add members to this team."}, status=status.HTTP_403_FORBIDDEN)
        
        except Team.DoesNotExist:
            return Response({"error": "Team not found"}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = AddRemoveTeamMembersSerializer(data=request.data)
        if serializer.is_valid():
            user_id = serializer.validated_data["user_id"]

            user = get_object_or_404(User, id=user_id)

            member = TeamMembers.objects.filter(team=team, user=user).first()
            if not member:
                return Response({"error": "User is not a member of this team."}, status=status.HTTP_400_BAD_REQUEST)

            member.delete()
            return Response({"message": "User removed from team successfully."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class TaskCreateView(APIView):
    @swagger_auto_schema(tags=['Task Management'],request_body=TaskSerializer)
    def post(self, request, team_id):
        try:
            team = Team.objects.get(id = team_id)
            user_role = TeamMembers.objects.filter(team = team, user = request.user).first()

            if user_role is None or user_role.role not in ['admin','manager']:
                return Response({"error": "You do not have permission to add or create task to this team."}, status=status.HTTP_403_FORBIDDEN)
        except Team.DoesNotExist:
            return Response({"error": "Team not found"}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = TaskSerializer(data = request.data)
        print("#")
        if serializer.is_valid():
            title = serializer.validated_data['title']
            description = serializer.validated_data['description']
            state = serializer.validated_data['status']
            priority = serializer.validated_data['priority']
            deadline = serializer.validated_data['deadline']
            creator = user_role.user
            assignee = serializer.validated_data['assignee']
            print(assignee)
            reviewer = serializer.validated_data['reviewer']
            print(reviewer)

            try:
                print('1')
                task = Task.objects.get(title = title)
                return Response({"error": "Task already exists."}, status=status.HTTP_400_BAD_REQUEST)
            except Task.DoesNotExist:
                print('2')
                task = Task.objects.create(title=title, description=description, status=state, priority=priority, 
                                           deadline= deadline,creator = creator, assignee = assignee, reviewer= reviewer, team = team)
                
                task_data = TaskSerializer(task).data
                return Response(task_data)
        
        print("*")
        return Response({
            'status' : False,
            'message' : 'Something Wrong'
        })
    
class TaskUpdateView(APIView):
    @swagger_auto_schema(tags=['Task Management'], request_body=TaskUpdationSerializer)
    def post(self, request, team_id):
        print(request.data)
        task_id = request.data.get('task_id')
        try:
            # task = Task.objects.get(id = task_id)
            task_assignee = Task.objects.filter(id = task_id, assignee = request.user)
            task_creator = Task.objects.filter(id = task_id, creator = request.user)
            # serializer = TaskSerializer(task_assignee, many=True)
            # data = JSONRenderer().render(serializer.data)
            team = Team.objects.get(id = team_id)
            user_role = TeamMembers.objects.filter(team = team, user = request.user).first()

            if user_role.role == 'manager':
                serializer = TaskUpdationSerializer(data= request.data)
                if serializer.is_valid():
                    description = serializer.data.get('description')
                    priority = serializer.data.get('priority')
                    assignee = serializer.data.get('assignee')

                    task = Task.objects.filter(id = task_id).update(description= description, priority= priority, assignee= assignee)
                    task_data = TaskSerializer(task, many=True)

                    return Response(task_data.data)
            
            elif task_assignee:
                serializer = TaskUpdationSerializer(data= request.data)
                if serializer.is_valid():
                    description = serializer.data.get('description')
                    priority = serializer.data.get('priority')
                    assignee = serializer.data.get('assignee')

                    task = Task.objects.filter(id = task_id, assignee = request.user).update(description= description, priority= priority, assignee= assignee)
                    task_data = TaskSerializer(task, many=True)

                    return Response(task_data.data)
            
            elif task_creator:
                serializer = TaskUpdationSerializer(data= request.data)
                if serializer.is_valid():
                    description = serializer.data.get('description')
                    priority = serializer.data.get('priority')
                    assignee = serializer.data.get('assignee')

                    task = Task.objects.filter(id = task_id, creator = request.user).update(description= description, priority= priority, assignee= assignee)
                    task_data = TaskSerializer(task, many=True)

                    return Response(task_data.data)
                
            elif not task_assignee or not task_creator:
                return Response({"message":"Your missing something or wrong data shared"}, status=status.HTTP_400_BAD_REQUEST)
        
        except Task.DoesNotExist:
            return Response({"error": "Task not found"}, status=status.HTTP_404_NOT_FOUND)
    
class TaskDeleteView(APIView):
    @swagger_auto_schema(tags=['Task Management'], request_body=TaskUpdationSerializer)
    def post(self, request,team_id):
        try:
            team = Team.objects.get(id = team_id)
            print(team)
            user_role = TeamMembers.objects.filter(team=team, user=request.user).first()

            if user_role is None or user_role.role not in ['admin', 'manager']:
                return Response({"error": "You do not have permission to add members to this team."}, status=status.HTTP_403_FORBIDDEN)
            else:
                serializer = TaskUpdationSerializer(data= request.data)
                if serializer.is_valid():
                    task_id = serializer.data.get('task_id')
                    task = Task.objects.filter(id = task_id, team= team)
                    print(task)
                    if not task:
                        return Response({"error": "Task is not exist in the team."}, status=status.HTTP_400_BAD_REQUEST)

                    task.delete()
                    return Response({"message": "Task removed from team successfully."}, status=status.HTTP_200_OK)

                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        except Team.DoesNotExist:
            return Response({"error": "Team not found"}, status=status.HTTP_404_NOT_FOUND)
        
class TaskView(APIView):
    @swagger_auto_schema(tags=['Task Management'])
    def post(self, request, team_id):
        try:
            team = Team.objects.get(id = team_id)
            user_role = TeamMembers.objects.filter(team = team, user = request.user).first()
            print(user_role.id)
            print(user_role.user)
            print(request.user.id)

            if user_role.role not in ['admin', 'manager']:
                print('if #1')
                print(team)
                task = Task.objects.filter(team = team, assignee = user_role.user)
                print(task)
                print()
                serializer = TaskSerializer(task, many=True)
                return Response({
                    'Message':'This task are assigned to the perticular team member',
                    'data' : serializer.data
                })
                
            elif user_role is None:
                return Response({"error":"The user don't have any task to do."}, status=status.HTTP_404_NOT_FOUND)
            else:
                task = Task.objects.get(team = team)
                serializer = TaskSerializer(task)
                return Response({"Role":"Admin,Manager", 'data':serializer.data})

        except Team.DoesNotExist:
            return Response({"error": "Team not found"}, status=status.HTTP_404_NOT_FOUND)
        
class TaskSortFilter(APIView):
    @swagger_auto_schema(tags=['Task Management'], request_body=TaskFilteringSerializer)
    def post(self, request):

        serializer = TaskFilteringSerializer(data = request.data)

        if serializer.is_valid():
            choice = serializer.data.get('choice')
            match choice:
                case 'status':
                    tasks = Task.objects.all().order_by(choice)
                    serializer = TaskSerializer(tasks, many=True)
                    return Response(serializer.data)
                
                case 'priority':
                    tasks = Task.objects.all().order_by(choice)
                    serializer = TaskSerializer(tasks, many=True)
                    return Response(serializer.data)
                
                case 'deadline':
                    tasks = Task.objects.all().order_by(choice)
                    serializer = TaskSerializer(tasks, many=True)
                    return Response(serializer.data)
                
                case 'creation_Date':
                    tasks = Task.objects.all().order_by(choice)
                    serializer = TaskSerializer(tasks, many=True)
                    return Response(serializer.data)
                
                case 'assignee':
                    tasks = Task.objects.all().order_by(choice)
                    serializer = TaskSerializer(tasks, many=True)
                    return Response(serializer.data)

        return Response({'error':'Something wrong'})