from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, Optional
from app.models import UserRole
from app.password_validation import validate_password_policy

class UserForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[Optional(), validate_password_policy]) # Required for new, optional for edit
    role = SelectField('Role', choices=[
        (UserRole.STAFF.value, 'Staff'),
        (UserRole.MANAGER.value, 'Manager')
    ])
    status = SelectField('Status', choices=[('active', 'Active'), ('inactive', 'Inactive')])
    submit = SubmitField('Save User')

class UserGroupForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    description = StringField('Description')
    submit = SubmitField('Save Group')
