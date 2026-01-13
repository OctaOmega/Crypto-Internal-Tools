import re
from wtforms.validators import ValidationError

def validate_password_policy(form, field):
    password = field.data
    if not password:
        return
        
    if len(password) < 8:
        raise ValidationError('Password must be at least 8 characters long.')
        
    if not re.search(r"[A-Z]", password):
        raise ValidationError('Password must contain at least one uppercase letter.')
        
    if not re.search(r"[^a-zA-Z0-9]", password):
        raise ValidationError('Password must contain at least one special character.')
