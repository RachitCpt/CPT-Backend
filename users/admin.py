from django.contrib import admin
from .models import *

# Register your models here.
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

class UserModelAdmin(BaseUserAdmin):
  # The fields to be used in displaying the User model.
  # These override the definitions on the base UserModelAdmin
  # that reference specific fields on auth.User.
  list_display = ('id', 'email', 'f_name', 'l_name', 'get_role')
  def get_role(self, obj):
      if obj.is_admin:
          return "SuperAdmin"
      return ", ".join([role.role_name for role in obj.roles.all()])
  get_role.short_description = 'Role'

  list_filter = ('is_admin',)
  fieldsets = (
      ('User Credentials', {'fields': ('email', 'password')}),
      ('Permissions', {'fields': ('roles',)}),
  )
  # add_fieldsets is not a standard ModelAdmin attribute. UserModelAdmin
  # overrides get_fieldsets to use this attribute when creating a user.
  add_fieldsets = (
      (None, {
          'classes': ('wide',),
          'fields': ('email', 'f_name', 'l_name', 'mobile_number', 'password1', 'password2', 'roles'),
      }),
  )
  search_fields = ('email',)
  ordering = ('id', 'email')
  filter_horizontal = ('roles',)


class RoleMasterAdmin(admin.ModelAdmin):
    list_display = ['id', 'role_name', 'get_pages']  # Display role name and id in the list view

    search_fields = ['role_name']       # Add search functionality by role name
    ordering = ['role_name']            # Order the list by role name

    # Add a horizontal filter for pages (many-to-many relationship)
    filter_horizontal = ['pages']  
    def get_pages(self, obj):
        return ", ".join([page.page_name for page in obj.pages.all()])
    get_pages.short_description = 'Pages'

class PageMasterAdmin(admin.ModelAdmin):
    list_display = ['id', 'page_name']  # Columns to display in the list view
    search_fields = ['page_name']       # Add search functionality by page name
    ordering = ['page_name']

admin.site.register(User, UserModelAdmin)
admin.site.register(RoleMaster, RoleMasterAdmin)
admin.site.register(PageMaster, PageMasterAdmin)