from rest_framework import permissions

class TodoPermission(permissions.BasePermission):
  def has_permission(self, request, view):
    return super().has_permission(request, view)
  
  def has_object_permission(self, request, view, obj):
    if obj.user == request.user.user or request.user.is_superuser:
      return True
    
    return False