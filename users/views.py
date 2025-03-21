from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import User, RoleMaster, PageMaster
from .serializers import UserSerializer, UserLoginSerializer, UserProfileSerializer, RoleMasterSerializer, RoleMasterUpdateSerializer, PageMasterSerializer, UserCreationSerializer
from .serializers import JobOpeningSerializer
from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from users.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework.permissions import IsAuthenticated
from requests_oauthlib import OAuth1
import requests
import json
import openpyxl

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


# def refresh_access_token_if_expired(request):
#     try:
#         access_token = AccessToken(request.auth)  # Validate the access token
#     except (TokenError, InvalidToken):
#         # If access token is invalid or expired, try to refresh it using the refresh token
#         refresh_token = request.data.get('refresh')
#         if not refresh_token:
#             return Response({'error': 'Refresh token is missing or invalid.'}, status=status.HTTP_401_UNAUTHORIZED)

#         try:
#             refresh = RefreshToken(refresh_token)
#             new_access_token = str(refresh.access_token)
#             return new_access_token
#         except TokenError:
#             return None
        

class CreateUserView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request):
        serializer = UserCreationSerializer(data=request.data)
        
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()  # Calls the create method in serializer
            token = get_tokens_for_user(user)  # Generates JWT tokens for the user
            return Response({
                'token': token,
                'msg': 'Registration successful',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request):
     #   email = request.data.get('email')
      #  password = request.data.get('password')
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get("email")
            password = serializer.data.get("password")
        user = authenticate(request, email=email, password=password)
        if user is not None:
            token = get_tokens_for_user(user)
            return Response({'token': token,'msg':'Login Succesfully'}, status=status.HTTP_200_OK)
        return Response({'error': 'Invalid Credentials'}, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
  renderer_classes = [UserRenderer]
  permission_classes = [IsAuthenticated]
  def get(self, request, format=None):
    serializer = UserProfileSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)


class MasterRolesView(APIView):
  renderer_classes = [UserRenderer]
  permission_classes = [IsAuthenticated]
  def get(self, request):
        roles = RoleMaster.objects.all()  # Fetch all roles from the database
        serializer = RoleMasterSerializer(roles, many=True)  # Serialize the roles
        return Response(serializer.data, status=status.HTTP_200_OK)
  
class RoleListView(APIView):
    def get(self, request):
        roles = RoleMaster.objects.all()
        serializer = RoleMasterSerializer(roles, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = RoleMasterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class ExternalApiView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request):
        url = 'https://7460199.restlets.api.netsuite.com/app/site/hosting/restlet.nl?script=161&deploy=1'

        # OAuth1 credentials
        oauth = OAuth1(
            client_key= '54913b83c310dc288c14b446c9024c58fab9a91ea10d4fa40289aa4d23f4a58b',
            # consumer_key = '54913b83c310dc288c14b446c9024c58fab9a91ea10d4fa40289aa4d23f4a58b',
            client_secret = '9dc4a158efe80561c042b5bb1df30b67f89d14ea900e0202e18b02365f5b526f',
            resource_owner_key = '3a48f6c255f6f38da29759a3bec5eb14b090918bb385032230e9b8106a9b6795',
            resource_owner_secret = 'eef8a6efa3838435f1a9ca2659e34366885ecb6cbe5f0e24bf768bf448550177',  # Replace with your actual resource owner secret
            signature_method='HMAC-SHA256',
            signature_type='auth_header',
            realm='7460199',
            force_include_body=True
        )

        # The data to be sent in the request body
        data = {
            "fromDate": request.data.get('fromDate'),
            "toDate": request.data.get('toDate')
        }

        # Include the cookies if needed
        cookies = {
            'ak_bmsc': 'BED5C95237675ECB4A85CE9BE734A38A~000000000000000000000000000000~YAAQUEo5F14WLXKSAQAAr/KnshkajrsGMLPf9WwldghQA2tCaQDAEZO9G5B+c+DZFFGQ265SvGqOoDXJ5k6mg+OXwrIslmxJ5lckjPiO+jby0obibFivvZcpqKhlZo8WmTyIEwIzlAdnMcpccFYkv5vOEjzhHgz/VzMvLSFiVnMqoiJT6PhtoW4VCKH5J7XW2Yyy22J8YkjHLDySWsOpocHKCsZnAoGXVDmTqb8DU9VKf1wsAPjgAa2Rvt3sSebqtySAD1Ac/y8dTy2qucrn2xJUHN7bmsOO22UbIwpwV04EXtQHBOuGMJ8WSNJMdNPTKbyMLfA7+zNMgGVl2bPsupMyDo8gOTKHOcZacvfbXYjvgmTFyHph2AVMgK8KeHdLlFbkW2QJ6pejQQ==',
            'bm_sv': '782EAD8E3692FAC95221CFE3BA0E6285~YAAQUEo5FyQxLXKSAQAAgUWxshliaVd1/u5RRF+jkyhdiNFtiWTfeNks7MBXgH1aPz2wAirQBgm4IVZrXMTfe2oZwe7vvwXagTpAeya3JdJHnO7+X9FpxZ/8x7fb59x0lOLet+IWHrbhnSW1kEbm48msd490fW9OY4jZyiW0Wq4lEqa1TIe6g0LSeRrppLAv/ptNvdCrlHUNZZGsAudC3vmqAV2xDzj9K6gGJAim4Hnyf3q6K8A01hoRspzpszDn4ZK93rGb8vNLKsNwis3I~1'
        }

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'OAuth realm="7460199",oauth_version="1.0"',  # Explicitly setting realm and version'
            'Connection': 'keep-alive'
        }

        try:
            # Make the request with OAuth1 authentication
            response = requests.post(url, auth=oauth,headers=headers, cookies=cookies, json=data)
            response.raise_for_status()  # Raise an error for bad responses
            return Response(response.json(), status=response.status_code)

        except requests.exceptions.HTTPError as http_err:
            return Response({'error': str(http_err)}, status=response.status_code)

        except Exception as err:
            return Response({'error': str(err)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetAssigneeExternalApiView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self, request):
        url = 'https://7460199.restlets.api.netsuite.com/app/site/hosting/restlet.nl?script=162&deploy=1'

        # OAuth1 credentials
        oauth = OAuth1(
            client_key= '54913b83c310dc288c14b446c9024c58fab9a91ea10d4fa40289aa4d23f4a58b',
            # consumer_key = '54913b83c310dc288c14b446c9024c58fab9a91ea10d4fa40289aa4d23f4a58b',
            client_secret = '9dc4a158efe80561c042b5bb1df30b67f89d14ea900e0202e18b02365f5b526f',
            resource_owner_key = '3a48f6c255f6f38da29759a3bec5eb14b090918bb385032230e9b8106a9b6795',
            resource_owner_secret = 'eef8a6efa3838435f1a9ca2659e34366885ecb6cbe5f0e24bf768bf448550177',  # Replace with your actual resource owner secret
            signature_method='HMAC-SHA256',
            realm='7460199'
        )

        

        # Include the cookies if needed
        cookies = {
            'ak_bmsc': 'C98C8316CC8E00E47D2B766E767158E8~000000000000000000000000000000~YAAQBo0sMUQ5pmiSAQAAG5qkxhnkjyPwMMJ6cVxXqdYR/W3C5nZjL8c18p7B5UR5ojLAyLTg+P8ekAf6nAV7CIsxZukt0pLl1i4Q/XJYXSsVyFKrpK5LtWulyE+pOLuI38xnft/UpwDFx5ZPEhx9STCB98JwvCXJQ5HX8EUzgo0uDxdRokOv7X+aJBXikQPxSh6rsk3HJKh76MhRZNd4X/llMiNIOwyK5u39jIwpbdQsOSexoVwAS9B5/dMa8DMEbi5veKTMf/e+6p917ecwCImv5SiHiDSbVuMuYsX8XyD0um0EIOT5Gg6U9wrroJfTjBV02c5Bk4eQO/au8as1lAZAjUKXuo5DGE0n1dT5pqGHiJJ0mdHrW2Hm',
            'bm_sv': '20D3A6113735F17E8397668257447C65~YAAQFI0sMXNS7oySAQAAbM+qxhkJ1VR/Lzjjq9iUJMQXbU6ThCalkHW2CIdgS8zGKI8B8f9R4qcYw/q1rcY7b6B6OOKaP1PTfNm552/LabHJ8+Zp2y07ouqJgLjrDmOVFLTls5K75vviSi6R8UsMslBr5PqfaXr2uc2HP8O05g9d/vqz/v/5Fj3euHIYJpsL9xUYc9ebn0YJaQ6ljz+0r0RDGko7OPvAXC9a7MKtarVxHoJ18oZwCR42QSDdr2HB1R/eIQMqwpQkWGflaJzj~1'
        }

        headers = {
            'Content-Type': 'application/json'
           
        }

        try:
            # Make the request with OAuth1 authentication
            response = requests.get(url, auth=oauth,headers=headers, cookies=cookies)
            response.raise_for_status()  # Raise an error for bad responses
            print("Status Code:", response.status_code)
            print("Response Content:", response.content)
            return Response(response.json(), status=response.status_code)

        except requests.exceptions.HTTPError as http_err:
            return Response({'error': str(http_err)}, status=response.status_code)

        except Exception as err:
            return Response({'error': str(err)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class UpdateCaseExternalApiView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request):
        url = 'https://7460199.restlets.api.netsuite.com/app/site/hosting/restlet.nl?script=132&deploy=1'

        # OAuth1 credentials
        oauth = OAuth1(
            client_key= '54913b83c310dc288c14b446c9024c58fab9a91ea10d4fa40289aa4d23f4a58b',
            # consumer_key = '54913b83c310dc288c14b446c9024c58fab9a91ea10d4fa40289aa4d23f4a58b',
            client_secret = '9dc4a158efe80561c042b5bb1df30b67f89d14ea900e0202e18b02365f5b526f',
            resource_owner_key = '3a48f6c255f6f38da29759a3bec5eb14b090918bb385032230e9b8106a9b6795',
            resource_owner_secret = 'eef8a6efa3838435f1a9ca2659e34366885ecb6cbe5f0e24bf768bf448550177',  # Replace with your actual resource owner secret
            signature_method='HMAC-SHA256',
            signature_type='auth_header',
            realm='7460199',
            force_include_body=True
        )

        # The data to be sent in the request body
        data = {
            "number" : request.data.get('number'),
            "status": request.data.get('status'),
            "message": request.data.get('message'),
            "priority" : request.data.get('priority'),
            "assignedto" : request.data.get('assignedto'),
            "startdate" : request.data.get('startdate'),
            "enddate" : request.data.get('enddate'),
            "hours_spent" : request.data.get('hours_spent'),
            "task_doneby" : request.data.get('task_doneby')
        }

        # Include the cookies if needed
        cookies = {
            'ak_bmsc': 'C98C8316CC8E00E47D2B766E767158E8~000000000000000000000000000000~YAAQBo0sMUQ5pmiSAQAAG5qkxhnkjyPwMMJ6cVxXqdYR/W3C5nZjL8c18p7B5UR5ojLAyLTg+P8ekAf6nAV7CIsxZukt0pLl1i4Q/XJYXSsVyFKrpK5LtWulyE+pOLuI38xnft/UpwDFx5ZPEhx9STCB98JwvCXJQ5HX8EUzgo0uDxdRokOv7X+aJBXikQPxSh6rsk3HJKh76MhRZNd4X/llMiNIOwyK5u39jIwpbdQsOSexoVwAS9B5/dMa8DMEbi5veKTMf/e+6p917ecwCImv5SiHiDSbVuMuYsX8XyD0um0EIOT5Gg6U9wrroJfTjBV02c5Bk4eQO/au8as1lAZAjUKXuo5DGE0n1dT5pqGHiJJ0mdHrW2Hm',
            'bm_sv': '20D3A6113735F17E8397668257447C65~YAAQFI0sMdBm7oySAQAA5+Wxxhku6SrhANBvghDFhCw+lSZN3V30ZTPT3dcDdi4geF8fRFrRF6WWpqxTXP0Gx6n0OzDQNFxNO0Owv5VDqd9UkV4SaXx20/fC05PuFrpyw4euyokHp8wiHTtQxcp/5LsyNBC0PX11eZHaCWMEqD6eQMukyNeO8ZTDg9iZekYMAfOZdoJIS7W4hHvcpq93VXYEBZi0epPtPiAANeQltd0Mb7ruq1yMNeGj/wv/u8JYiGqAatYXWI4E2uEmJWTE~1'
        }

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'OAuth realm="7460199",oauth_version="1.0"',  # Explicitly setting realm and version'
            'Connection': 'keep-alive'
        }

        try:
            # Make the request with OAuth1 authentication
            response = requests.post(url, auth=oauth,headers=headers, cookies=cookies, json=data)
            response.raise_for_status()  # Raise an error for bad responses
            print("Status Code:", response.status_code)
            print("Response Content:", response.content)
            return Response(response.json(), status=response.status_code)

        except requests.exceptions.HTTPError as http_err:
            return Response({'error': str(http_err)}, status=response.status_code)

        except Exception as err:
            return Response({'error': str(err)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class CreateRoleView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]  # Only authenticated users can create roles

    def post(self, request):
        serializer = RoleMasterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class UpdateRoleView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def put(self, request, pk):
        try:
            role = RoleMaster.objects.get(pk=pk)
        except RoleMaster.DoesNotExist:
            return Response({"error": "Role not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = RoleMasterUpdateSerializer(role, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class PageListView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self, request):
        pages = PageMaster.objects.all()
        serializer = PageMasterSerializer(pages, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

class UserListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Check if the user has the Admin role
        if request.user.roles.filter(role_name='Admin').exists():
            users = User.objects.all().order_by('id')  # Get all users
            serializer = UserSerializer(users, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'You do not have permission to view this list.'}, 
                            status=status.HTTP_403_FORBIDDEN)
    
class UpdateUserRoleView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, user_id):
        # Check if the user has the Admin role
        if not request.user.roles.filter(role_name='Admin').exists():
            return Response({'error': 'You do not have permission to perform this action.'}, 
                            status=status.HTTP_403_FORBIDDEN)

        # Retrieve the user to be updated
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Extract data from request
        first_name = request.data.get('f_name')
        last_name = request.data.get('l_name')
        email = request.data.get('email')
        mobile = request.data.get('mobile_number')
        role_ids = request.data.get('roles', [])

        # Validate roles
        if not role_ids:
            return Response({'error': 'No roles provided.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if all provided role IDs exist
        roles = RoleMaster.objects.filter(id__in=role_ids)
        if len(roles) != len(role_ids):
            return Response({'error': 'One or more roles not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Update user's details
        user.f_name = first_name
        user.l_name = last_name
        user.email = email
        user.mobile_number = mobile
        user.roles.set(roles)  # Set roles, replacing any previous roles
        user.save()

        # Serialize and return the updated user data
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ProjectCaseExternalApiView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request):
        url = 'https://7460199.restlets.api.netsuite.com/app/site/hosting/restlet.nl?script=263&deploy=1'

        # OAuth1 credentials
        oauth = OAuth1(
            client_key= '54913b83c310dc288c14b446c9024c58fab9a91ea10d4fa40289aa4d23f4a58b',
            # consumer_key = '54913b83c310dc288c14b446c9024c58fab9a91ea10d4fa40289aa4d23f4a58b',
            client_secret = '9dc4a158efe80561c042b5bb1df30b67f89d14ea900e0202e18b02365f5b526f',
            resource_owner_key = '3a48f6c255f6f38da29759a3bec5eb14b090918bb385032230e9b8106a9b6795',
            resource_owner_secret = 'eef8a6efa3838435f1a9ca2659e34366885ecb6cbe5f0e24bf768bf448550177',  # Replace with your actual resource owner secret
            signature_method='HMAC-SHA256',
            signature_type='auth_header',
            realm='7460199',
            force_include_body=True
        )

        # The data to be sent in the request body
        data = {
            "fromDate": request.data.get('fromDate'),
            "endDate": request.data.get('endDate')
        }

        # Include the cookies if needed
        cookies = {
            'ak_bmsc': 'C98C8316CC8E00E47D2B766E767158E8~000000000000000000000000000000~YAAQBo0sMUQ5pmiSAQAAG5qkxhnkjyPwMMJ6cVxXqdYR/W3C5nZjL8c18p7B5UR5ojLAyLTg+P8ekAf6nAV7CIsxZukt0pLl1i4Q/XJYXSsVyFKrpK5LtWulyE+pOLuI38xnft/UpwDFx5ZPEhx9STCB98JwvCXJQ5HX8EUzgo0uDxdRokOv7X+aJBXikQPxSh6rsk3HJKh76MhRZNd4X/llMiNIOwyK5u39jIwpbdQsOSexoVwAS9B5/dMa8DMEbi5veKTMf/e+6p917ecwCImv5SiHiDSbVuMuYsX8XyD0um0EIOT5Gg6U9wrroJfTjBV02c5Bk4eQO/au8as1lAZAjUKXuo5DGE0n1dT5pqGHiJJ0mdHrW2Hm',
            'bm_sv': '20D3A6113735F17E8397668257447C65~YAAQFI0sMdBm7oySAQAA5+Wxxhku6SrhANBvghDFhCw+lSZN3V30ZTPT3dcDdi4geF8fRFrRF6WWpqxTXP0Gx6n0OzDQNFxNO0Owv5VDqd9UkV4SaXx20/fC05PuFrpyw4euyokHp8wiHTtQxcp/5LsyNBC0PX11eZHaCWMEqD6eQMukyNeO8ZTDg9iZekYMAfOZdoJIS7W4hHvcpq93VXYEBZi0epPtPiAANeQltd0Mb7ruq1yMNeGj/wv/u8JYiGqAatYXWI4E2uEmJWTE~1'
        }

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'OAuth realm="7460199",oauth_version="1.0"',  # Explicitly setting realm and version'
            'Connection': 'keep-alive'
        }

        try:
            # Make the request with OAuth1 authentication
            response = requests.post(url, auth=oauth,headers=headers, cookies=cookies, json=data)
            response.raise_for_status()  # Raise an error for bad responses
            print("Status Code:", response.status_code)
            print("Response Content:", response.content)
            return Response(response.json(), status=response.status_code)

        except requests.exceptions.HTTPError as http_err:
            return Response({'error': str(http_err)}, status=response.status_code)

        except Exception as err:
            return Response({'error': str(err)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class SetProjectCaseExternalApiView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request):
        url = 'https://7460199.restlets.api.netsuite.com/app/site/hosting/restlet.nl?script=264&deploy=1'

        # OAuth1 credentials
        oauth = OAuth1(
            client_key= '54913b83c310dc288c14b446c9024c58fab9a91ea10d4fa40289aa4d23f4a58b',
            # consumer_key = '54913b83c310dc288c14b446c9024c58fab9a91ea10d4fa40289aa4d23f4a58b',
            client_secret = '9dc4a158efe80561c042b5bb1df30b67f89d14ea900e0202e18b02365f5b526f',
            resource_owner_key = '3a48f6c255f6f38da29759a3bec5eb14b090918bb385032230e9b8106a9b6795',
            resource_owner_secret = 'eef8a6efa3838435f1a9ca2659e34366885ecb6cbe5f0e24bf768bf448550177',  # Replace with your actual resource owner secret
            signature_method='HMAC-SHA256',
            signature_type='auth_header',
            realm='7460199',
            force_include_body=True
        )

        # The data to be sent in the request body
        data = {
            "project": request.data.get('project'),
            "projectTask": request.data.get('projectTask'),
            "startDate": request.data.get('startDate'),
            "endDate": request.data.get('endDate'),
            "hours": request.data.get('hours'),
            "taskDoneBy": request.data.get('taskDoneBy')
        }

        # Include the cookies if needed
        cookies = {
            'ak_bmsc': 'C98C8316CC8E00E47D2B766E767158E8~000000000000000000000000000000~YAAQBo0sMUQ5pmiSAQAAG5qkxhnkjyPwMMJ6cVxXqdYR/W3C5nZjL8c18p7B5UR5ojLAyLTg+P8ekAf6nAV7CIsxZukt0pLl1i4Q/XJYXSsVyFKrpK5LtWulyE+pOLuI38xnft/UpwDFx5ZPEhx9STCB98JwvCXJQ5HX8EUzgo0uDxdRokOv7X+aJBXikQPxSh6rsk3HJKh76MhRZNd4X/llMiNIOwyK5u39jIwpbdQsOSexoVwAS9B5/dMa8DMEbi5veKTMf/e+6p917ecwCImv5SiHiDSbVuMuYsX8XyD0um0EIOT5Gg6U9wrroJfTjBV02c5Bk4eQO/au8as1lAZAjUKXuo5DGE0n1dT5pqGHiJJ0mdHrW2Hm',
            'bm_sv': '20D3A6113735F17E8397668257447C65~YAAQFI0sMdBm7oySAQAA5+Wxxhku6SrhANBvghDFhCw+lSZN3V30ZTPT3dcDdi4geF8fRFrRF6WWpqxTXP0Gx6n0OzDQNFxNO0Owv5VDqd9UkV4SaXx20/fC05PuFrpyw4euyokHp8wiHTtQxcp/5LsyNBC0PX11eZHaCWMEqD6eQMukyNeO8ZTDg9iZekYMAfOZdoJIS7W4hHvcpq93VXYEBZi0epPtPiAANeQltd0Mb7ruq1yMNeGj/wv/u8JYiGqAatYXWI4E2uEmJWTE~1'
        }

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'OAuth realm="7460199",oauth_version="1.0"',  # Explicitly setting realm and version'
            'Connection': 'keep-alive'
        }

        try:
            # Make the request with OAuth1 authentication
            response = requests.post(url, auth=oauth,headers=headers, cookies=cookies, json=data)
            response.raise_for_status()  # Raise an error for bad responses
            print("Status Code:", response.status_code)
            print("Response Content:", response.content)
            return Response(response.json(), status=response.status_code)

        except requests.exceptions.HTTPError as http_err:
            return Response({'error': str(http_err)}, status=response.status_code)

        except Exception as err:
            return Response({'error': str(err)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class JobOpeningList(APIView):
    def get(self, request):
        # Path to the Excel file
        file_path = '../data/job_opening.xlsx'
        #file_path = 'D:/Connate/ConnatePeople Final Website/job_opening.xlsx'
        wb = openpyxl.load_workbook(file_path)
        sheet = wb.active
 
        # Extract rows (skipping the header row)
        rows = list(sheet.iter_rows(values_only=True))[1:]
 
        job_openings = []
        for row in rows:
            job_openings.append({
                'technology': row[0],  # assuming job title is in the first column
                'job_description': row[1],   # location in the second column
                'experience': row[2],   # job type in the third column
                'location': row[3],     # salary in the fourth column
            })
 
        # Serialize the data
        serializer = JobOpeningSerializer(job_openings, many=True)
 
        # Return the data as JSON
        return Response(serializer.data)