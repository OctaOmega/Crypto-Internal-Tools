from functools import wraps
from flask import abort
from flask_login import current_user
from app.models import UserRole

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return abort(401)
            if current_user.role not in roles and current_user.role != UserRole.ADMIN.value:
                return abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def manager_required(f):
    return role_required(UserRole.MANAGER.value)(f)

def staff_required(f):
    return role_required(UserRole.STAFF.value, UserRole.MANAGER.value)(f)
