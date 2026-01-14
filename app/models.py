from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import db, login
from enum import Enum

class UserRole(str, Enum):
    STAFF = 'staff'
    MANAGER = 'manager'
    ADMIN = 'admin'

class ModuleType(str, Enum):
    PDF = 'pdf'
    YOUTUBE = 'youtube'
    VIDEO = 'video'
    LINK = 'link'
    RICH_TEXT = 'rich_text'
    QUIZ = 'quiz'

class CourseStatus(str, Enum):
    DRAFT = 'draft'
    PUBLISHED = 'published'
    DISABLED = 'disabled'
    ARCHIVED = 'archived'

class EnrollmentStatus(str, Enum):
    ACTIVE = 'active'
    COMPLETED = 'completed'
    WITHDRAWN = 'withdrawn'

class ProgressStatus(str, Enum):
    NOT_STARTED = 'not_started'
    IN_PROGRESS = 'in_progress'
    COMPLETED = 'completed'

# Association Tables
user_groups = db.Table('user_group_association',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('user_group.id'), primary_key=True)
)

course_groups = db.Table('course_group_visibility',
    db.Column('course_id', db.Integer, db.ForeignKey('course.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('user_group.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), index=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(256))
    role = db.Column(db.String(20), default=UserRole.STAFF.value)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    # Relationships
    groups = db.relationship('UserGroup', secondary=user_groups, backref=db.backref('members', lazy='dynamic'))
    enrollments = db.relationship('Enrollment', foreign_keys='Enrollment.user_id', backref='student', lazy='dynamic', cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    # Auth Security
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    def get_reset_password_token(self, expires_in=600):
        # Implementation using PyJWT
        from flask import current_app
        import jwt
        from datetime import datetime, timedelta
        
        return jwt.encode(
            {'reset_password': self.id, 'exp': datetime.utcnow() + timedelta(seconds=expires_in)},
            current_app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_reset_password_token(token):
        from flask import current_app
        import jwt
        try:
            id = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])['reset_password']
        except:
            return None
        return User.query.get(id)

    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def is_manager(self):
        return self.role in [UserRole.MANAGER.value, UserRole.ADMIN.value]

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

class UserGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    description = db.Column(db.String(256))
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id')) # Owner/Creator

class TrainingGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    description = db.Column(db.String(256))
    courses = db.relationship('Course', backref='training_group', lazy='dynamic')

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(140))
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default=CourseStatus.DRAFT.value)
    training_group_id = db.Column(db.Integer, db.ForeignKey('training_group.id'))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.DateTime, nullable=True) # Optional due date
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    modules = db.relationship('CourseModule', backref='course', lazy='dynamic', cascade='all, delete-orphan')
    visible_to_groups = db.relationship('UserGroup', secondary=course_groups, backref='accessible_courses')

class CourseModule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    title = db.Column(db.String(140))
    type = db.Column(db.String(20), default=ModuleType.RICH_TEXT.value)
    order = db.Column(db.Integer, default=0)
    estimated_minutes = db.Column(db.Integer, default=5)
    content_url = db.Column(db.String(512)) # URL for video/link
    file_id = db.Column(db.Integer, db.ForeignKey('file_asset.id')) # For PDF/User uploads
    body_html = db.Column(db.Text) # For Rich Text
    is_required = db.Column(db.Boolean, default=True)
    
    file = db.relationship('FileAsset')

class FileAsset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256))
    storage_path = db.Column(db.String(512))
    mime_type = db.Column(db.String(64))
    size = db.Column(db.Integer)
    content_blob = db.Column(db.Text) # Base64 encoded content
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    enrolled_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime, nullable=True) # When user actually starts
    status = db.Column(db.String(20), default=EnrollmentStatus.ACTIVE.value)
    completed_at = db.Column(db.DateTime, nullable=True) # New field
    total_time_seconds = db.Column(db.Integer, default=0) # New field for KPIs
    assigned_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # None if self-enrolled
    
    course = db.relationship('Course', backref='enrollments')
    progress_records = db.relationship('ModuleProgress', backref='enrollment', lazy='dynamic')

class ModuleProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    enrollment_id = db.Column(db.Integer, db.ForeignKey('enrollment.id'))
    module_id = db.Column(db.Integer, db.ForeignKey('course_module.id'))
    status = db.Column(db.String(20), default=ProgressStatus.NOT_STARTED.value)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    total_time_seconds = db.Column(db.Integer, default=0)
    last_activity_at = db.Column(db.DateTime)
    
    module = db.relationship('CourseModule')

class NewsItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(20), default=ModuleType.RICH_TEXT.value) # Use ModuleType enums
    content_url = db.Column(db.String(512)) # YouTube/External Link
    file_id = db.Column(db.Integer, db.ForeignKey('file_asset.id'))
    body_html = db.Column(db.Text)
    
    is_published = db.Column(db.Boolean, default=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    file = db.relationship('FileAsset')
    author = db.relationship('User')

class ActivityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    target_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=True)
    module_id = db.Column(db.Integer, db.ForeignKey('course_module.id'), nullable=True)
    type = db.Column(db.String(50))
    metadata_json = db.Column(db.Text) # JSON string
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(140))
    message = db.Column(db.Text)
    link = db.Column(db.String(256)) # For deep linking
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Tool(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    description = db.Column(db.String(256))
    url = db.Column(db.String(512))
    internal_route = db.Column(db.String(64))
    icon = db.Column(db.String(64)) # FontAwesome class
    enabled = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
