from django.urls import path
from .views import CreateUserView, RoleListView
from .views import LoginView, UserProfileView, MasterRolesView, ExternalApiView, GetAssigneeExternalApiView, UpdateCaseExternalApiView, CreateRoleView, UpdateRoleView, PageListView, UserListView, UpdateUserRoleView
from .views import ProjectCaseExternalApiView, SetProjectCaseExternalApiView, JobOpeningList
urlpatterns = [
    path('create-user/', CreateUserView.as_view(), name='create-user'),
    path('login/', LoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('roles/', MasterRolesView.as_view(), name='roles-list'),
    path('create-role/', CreateRoleView.as_view(), name='create_role'),
    path('update-role/<int:pk>/', UpdateRoleView.as_view(), name='update_role'),
    path('pages/', PageListView.as_view(), name='page-list'),
    path('getCases/', ExternalApiView.as_view(), name='ticket-detail'),
    path('getAssignee/', GetAssigneeExternalApiView.as_view(), name='get-Assignee'),
    path('updateTicket/', UpdateCaseExternalApiView.as_view(), name='update-ticket'),
    path('users/', UserListView.as_view(), name='user-list'),
    path('users/<int:user_id>/role/', UpdateUserRoleView.as_view(), name='update-user-role'),
    path('getProject/', ProjectCaseExternalApiView.as_view(), name='Get-Projects'),
    path('setProject/', SetProjectCaseExternalApiView.as_view(), name='Set-Projects'),
    path('job-openings/', JobOpeningList.as_view(), name='job_openings_list'),
]

