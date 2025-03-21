from rest_framework import serializers
from .models import PageMaster, RoleMaster, User
from .models import RoleMaster, PageMaster

class PageMasterSerializer(serializers.ModelSerializer):
    class Meta:
        model = PageMaster
        fields = ['id', 'page_name', 'created_at', 'updated_at']

        
class RoleMasterSerializer(serializers.ModelSerializer):
    # Allow setting page IDs for the role
    page_ids = serializers.PrimaryKeyRelatedField(
        queryset=PageMaster.objects.all(), many=True, write_only=True
    )

    # Display pages for the role in the response
    pages = PageMasterSerializer(many=True, read_only=True)

    class Meta:
        model = RoleMaster
        fields = ['id', 'role_name', 'page_ids', 'pages']

    # Override the create method to handle page access
    def create(self, validated_data):
        page_ids = validated_data.pop('page_ids', [])
        role = RoleMaster.objects.create(**validated_data)
        role.pages.set(page_ids)  # Assign pages to the role
        return role

    # Override the update method to handle page access updates
    def update(self, instance, validated_data):
        page_ids = validated_data.pop('page_ids', None)
        instance.role_name = validated_data.get('role_name', instance.role_name)
        instance.save()

        # Update pages if page_ids is provided
        if page_ids is not None:
            instance.pages.set(page_ids)

        return instance


class UserSerializer(serializers.ModelSerializer):
    role_ids = serializers.PrimaryKeyRelatedField(
        queryset=RoleMaster.objects.all(), many=True, write_only=True, required=False
    )
    roles = RoleMasterSerializer(many=True, read_only=True)
    class Meta:
        model = User
        fields = ['f_name', 'l_name', 'email', 'password', 'mobile_number','roles','role_ids']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        role_ids = validated_data.pop('role_ids', None)
        user = User(
            f_name=validated_data['f_name'],
            l_name=validated_data['l_name'],
            email=validated_data['email'],
            mobile_number=validated_data['mobile_number'],
            

        )
        user.set_password(validated_data['password'])
        user.save()
        if role_ids:
            user.roles.set(role_ids)
        return user

class UserLoginSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    model = User
    fields = ['email', 'password']


class UserProfileSerializer(serializers.ModelSerializer):
  roles = RoleMasterSerializer(many=True, read_only=True)
  class Meta:
    model = User
    fields = ['id', 'email', 'f_name','l_name', 'mobile_number','roles']




class RoleMasterUpdateSerializer(serializers.ModelSerializer):
    pages = PageMasterSerializer(many=True, read_only=True)  # Use nested serializer for read-only display
    page_ids = serializers.PrimaryKeyRelatedField(queryset=PageMaster.objects.all(), many=True, write_only=True)  # For updating page IDs

    class Meta:
        model = RoleMaster
        fields = ['role_name', 'pages', 'page_ids']
    
    def update(self, instance, validated_data):
        # Update role name if provided
        instance.role_name = validated_data.get('role_name', instance.role_name)
        
        # Update the many-to-many relationship for pages
        page_ids = validated_data.get('page_ids')
        if page_ids:
            instance.pages.set(page_ids)  # Update pages with new list of page IDs

        instance.save()
        return instance
    

class UserSerializer(serializers.ModelSerializer):
    roles = RoleMasterSerializer(many=True, read_only=True,)  # Adjust according to your related name
    # roles = serializers.PrimaryKeyRelatedField(queryset=RoleMaster.objects.all(), many=True, required=False)

    class Meta:
        model = User
        fields = ['id', 'f_name', 'l_name', 'mobile_number','email', 'roles']  # 

    
class UserCreationSerializer(serializers.ModelSerializer):
    # roles = RoleMasterSerializer(many=True, read_only=True,)  # Adjust according to your related name
    roles = serializers.PrimaryKeyRelatedField(queryset=RoleMaster.objects.all(), many=True, required=False)
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['f_name','l_name', 'email', 'password', 'mobile_number', 'roles']

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = super().create(validated_data)
        user.set_password(password)  # This hashes the password
        user.save()
        return user

class JobOpeningSerializer(serializers.Serializer):
    technology   = serializers.CharField(max_length=200)
    job_description = serializers.CharField(max_length=200)
    experience = serializers.CharField(max_length=100)
    location = serializers.CharField(max_length=100)

