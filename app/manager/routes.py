from flask import render_template, redirect, url_for, flash, request, send_file, abort
from flask_login import login_required, current_user
from app import db
from app.manager import bp
from app.models import User, UserGroup, TrainingGroup, Course, CourseModule, Enrollment, Tool, CourseStatus, ModuleType, FileAsset, NewsItem, Notification, UserRole, EnrollmentStatus, ActivityEvent
from app.decorators import manager_required
import io
import pandas as pd
from datetime import datetime
from sqlalchemy import func, desc
from app.models import ModuleProgress


@bp.route('/dashboard')
@login_required
@manager_required
def dashboard():
    
    # Base Stats
    stats = {
        'total_users': User.query.count(),
        'total_courses': Course.query.count(),
        'published_courses': Course.query.filter_by(status=CourseStatus.PUBLISHED.value).count(),
        'active_enrollments': Enrollment.query.filter_by(status=EnrollmentStatus.ACTIVE.value).count(),
        'completions': Enrollment.query.filter_by(status=EnrollmentStatus.COMPLETED.value).count()
    }

    # Top 5 Popular Courses (by enrollment count)
    top_courses = db.session.query(
        Course.title,
        func.count(Enrollment.id).label('count')
    ).join(Enrollment).group_by(Course.id)\
     .order_by(desc('count')).limit(5).all()

    # Top 5 Active Users (by enrollment count)
    top_users_enrollments = db.session.query(
        User.name,
        func.count(Enrollment.id).label('count')
    ).join(Enrollment, User.id == Enrollment.user_id)\
     .group_by(User.id).order_by(desc('count')).limit(5).all()

    # Top 5 Learned Users (by time spent)
    top_users_time = db.session.query(
        User.name,
        func.sum(ModuleProgress.total_time_seconds).label('total_seconds')
    ).join(Enrollment, User.id == Enrollment.user_id)\
     .join(ModuleProgress, Enrollment.id == ModuleProgress.enrollment_id)\
     .group_by(User.id).order_by(desc('total_seconds')).limit(5).all()
     
    # Convert seconds to minutes for display
    top_users_time = [(u[0], round(u[1]/60, 1)) for u in top_users_time]

    # Group Stats
    group_stats = db.session.query(
        UserGroup.name,
        func.count(Enrollment.id).label('enrollment_count')
    ).join(UserGroup.members)\
     .join(Enrollment, User.id == Enrollment.user_id)\
     .group_by(UserGroup.id).all()

    recent_activity = ActivityEvent.query.order_by(ActivityEvent.created_at.desc()).limit(10).all()
    
    return render_template('manager/dashboard.html', 
                         title='Manager Dashboard', 
                         stats=stats, 
                         activity=recent_activity,
                         top_courses=top_courses,
                         top_users_enrollments=top_users_enrollments,
                         top_users_time=top_users_time,
                         group_stats=group_stats)

@bp.route('/courses')
@login_required
@manager_required
def courses():
    query = request.args.get('q', '')
    
    base_query = Course.query
    
    if query:
        base_query = base_query.filter(
            (Course.title.ilike(f'%{query}%')) | 
            (Course.description.ilike(f'%{query}%'))
        )
        
    courses = base_query.order_by(Course.created_at.desc()).all()
    return render_template('manager/courses.html', title='Manage Courses', courses=courses, query=query)

from app.manager.forms import CourseForm

@bp.route('/courses/new', methods=['GET', 'POST'])
@login_required
@manager_required
def new_course():
    form = CourseForm()
    if form.validate_on_submit():
        course = Course(
            title=form.title.data,
            description=form.description.data,
            status=form.status.data,
            due_date=form.due_date.data,
            training_group_id=form.training_group_id.data,
            created_by=current_user.id
        )
        db.session.add(course)
        db.session.commit()
        current_app.logger.info(f'Course created: {course.title} (ID: {course.id}) by {current_user.email}')
        
        # Trigger Notification for New Published Course
        if course.status == CourseStatus.PUBLISHED.value:
            users = User.query.filter(User.id != current_user.id).all() # Notify all except creator
            for user in users:
                # Check if user has access (simplified: notify all for now, or check group)
                # Ideally check: if course.visible_to_groups contains user.groups
                
                notif = Notification(
                    user_id=user.id,
                    title="New Course Available",
                    message=f"A new course '{course.title}' has been published.",
                    link=url_for('staff.course_detail', course_id=course.id)
                )
                db.session.add(notif)
            db.session.commit()
            
        flash('Course created successfully.', 'success')
        return redirect(url_for('manager.courses'))
    return render_template('manager/course_form.html', title='Create New Course', form=form)

@bp.route('/courses/<int:id>/delete', methods=['POST'])
@login_required
@manager_required
def delete_course(id):
    course = Course.query.get_or_404(id)
    
    # Permission Logic
    # Admin: Can delete at any stage
    # Manager: Can delete ONLY if Draft
    if current_user.role != UserRole.ADMIN.value:
        if course.status != CourseStatus.DRAFT.value:
            flash('Managers can only delete draft courses. Use Disable instead.', 'warning')
            return redirect(url_for('manager.courses'))
            
    db.session.delete(course)
    db.session.commit()
    current_app.logger.info(f'Course deleted: {course.title} (ID: {id}) by {current_user.email}')
    flash('Course deleted successfully.', 'success')
    return redirect(url_for('manager.courses'))

@bp.route('/courses/<int:id>/disable', methods=['POST'])
@login_required
@manager_required
def disable_course(id):
    course = Course.query.get_or_404(id)
    
    if course.status == CourseStatus.PUBLISHED.value:
        course.status = CourseStatus.DISABLED.value
        db.session.commit()
        current_app.logger.info(f'Course disabled: {course.title} (ID: {id}) by {current_user.email}')
        flash('Course disabled successfully.', 'success')
    else:
        flash('Only published courses can be disabled.', 'info')
        
    return redirect(url_for('manager.courses'))

@bp.route('/courses/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@manager_required
def edit_course(id):
    course = Course.query.get_or_404(id)
    form = CourseForm()
    if form.validate_on_submit():
        course.title = form.title.data
        course.description = form.description.data
        course.status = form.status.data
        course.due_date = form.due_date.data
        course.training_group_id = form.training_group_id.data
        db.session.commit()
        current_app.logger.info(f'Course updated: {course.title} (ID: {id}) by {current_user.email}')
        flash('Course updated successfully.', 'success')
        return redirect(url_for('manager.courses'))
    elif request.method == 'GET':
        form.title.data = course.title
        form.description.data = course.description
        form.due_date.data = course.due_date
        form.status.data = course.status
        form.training_group_id.data = course.training_group_id
        
    return render_template('manager/course_form.html', title='Edit Course', form=form)

from app.manager.forms_user import UserForm

@bp.route('/users')
@login_required
@manager_required
def users():
    users = User.query.all()
    return render_template('manager/users.html', title='Manage Users', users=users)

@bp.route('/users/<int:id>')
@login_required
@manager_required
def user_details(id):
    user = User.query.get_or_404(id)
    # Calculate extra stats for each enrollment
    enrollments = []
    for e in user.enrollments:
        total_seconds = sum(record.total_time_seconds for record in e.progress_records)
        
        # Calculate progress percent
        total_modules = e.course.modules.count()
        completed_modules = e.progress_records.filter_by(status='completed').count()
        progress_percent = int((completed_modules / total_modules * 100)) if total_modules > 0 else 0
        
        # Attach temporary attributes for template
        e.total_seconds = total_seconds
        e.progress_percent = progress_percent
        enrollments.append(e)
        
    return render_template('manager/user_details.html', title=user.name, user=user, enrollments=enrollments)

@bp.route('/users/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@manager_required
def edit_user(id):
    user = User.query.get_or_404(id)
    
    # Permissions Check: Manager cannot edit Admin
    # flash(f"Debug: You are '{current_user.role}' ({type(current_user.role)}), editing '{user.role}' ({type(user.role)}). Admin Val: {UserRole.ADMIN.value}", "warning")
    
    if user.role == UserRole.ADMIN.value and current_user.role != UserRole.ADMIN.value:
        abort(403)
        
    form = UserForm()
    
    # Restrict Role Choices
    if current_user.role == UserRole.MANAGER.value:
        form.role.choices = [(UserRole.STAFF.value, 'Staff')]
    elif current_user.role == UserRole.ADMIN.value:
         form.role.choices = [
             (UserRole.STAFF.value, 'Staff'),
             (UserRole.MANAGER.value, 'Manager'),
             (UserRole.ADMIN.value, 'Admin')
         ]
         
    if form.validate_on_submit():
        user.name = form.name.data
        user.email = form.email.data
        user.role = form.role.data
        user.status = form.status.data
        db.session.commit()
        current_app.logger.info(f'User updated: {user.email} (ID: {id}) by {current_user.email}')
        flash('User updated successfully.', 'success')
        return redirect(url_for('manager.users'))
    elif request.method == 'GET':
        form.name.data = user.name
        form.email.data = user.email
        form.role.data = user.role
        form.status.data = user.status
        
    return render_template('manager/user_form.html', title='Edit User', form=form)

@bp.route('/users/new', methods=['GET', 'POST'])
@login_required
@manager_required
def new_user():
    form = UserForm()
    
    # Restrict Role Choices
    if current_user.role == UserRole.MANAGER.value:
        form.role.choices = [(UserRole.STAFF.value, 'Staff')]
    elif current_user.role == UserRole.ADMIN.value:
         # Admin can create Managers and Staff, but not other Admins.
         # "a manager user can create users for staff role but not a manager or admin role"
         # "Only admin user has the option to create manager users"
         form.role.choices = [
             (UserRole.STAFF.value, 'Staff'),
             (UserRole.MANAGER.value, 'Manager')
         ]
         
    if form.validate_on_submit():
        if not form.password.data:
            flash('Password is required for new users.', 'danger')
            return render_template('manager/user_form.html', title='Onboard User', form=form)
            
        # Check if user already exists
        if User.query.filter_by(email=form.email.data).first():
            flash('User with this email already exists.', 'danger')
            return render_template('manager/user_form.html', title='Onboard User', form=form)
            
        user = User(
            name=form.name.data,
            email=form.email.data,
            role=form.role.data,
            status=form.status.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        current_app.logger.info(f'New user onboarded: {user.email} (ID: {user.id}) by {current_user.email}')
        flash('User onboarded successfully.', 'success')
        return redirect(url_for('manager.users'))
    return render_template('manager/user_form.html', title='Onboard User', form=form)

from app.manager.forms_user import UserGroupForm

@bp.route('/groups')
@login_required
@manager_required
def groups():
    groups = UserGroup.query.all()
    return render_template('manager/groups.html', title='Manage Groups', groups=groups)

@bp.route('/groups/new', methods=['GET', 'POST'])
@login_required
@manager_required
def new_group():
    form = UserGroupForm()
    if form.validate_on_submit():
        group = UserGroup(name=form.name.data, description=form.description.data, manager_id=current_user.id)
        db.session.add(group)
        db.session.commit()
        current_app.logger.info(f'Group created: {group.name} by {current_user.email}')
        flash('Group created.', 'success')
        return redirect(url_for('manager.groups'))
    return render_template('manager/group_form.html', title='New Group', form=form)

@bp.route('/users/<int:id>/delete', methods=['POST'])
@login_required
@manager_required
def delete_user(id):
    if current_user.role != UserRole.ADMIN.value:
        abort(403)
        
    user = User.query.get_or_404(id)
    if user.id == current_user.id:
        flash('You cannot delete yourself.', 'danger')
        return redirect(url_for('manager.users'))
        
    db.session.delete(user)
    db.session.commit()
    current_app.logger.info(f'User deleted: {user.email} (ID: {id}) by {current_user.email}')
    flash('User deleted successfully.', 'success')
    return redirect(url_for('manager.users'))

@bp.route('/groups/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@manager_required
def edit_group(id):
    group = UserGroup.query.get_or_404(id)
    form = UserGroupForm()
    if form.validate_on_submit():
        group.name = form.name.data
        group.description = form.description.data
        db.session.commit()
        current_app.logger.info(f'Group updated: {group.name} by {current_user.email}')
        flash('Group updated.', 'success')
        return redirect(url_for('manager.groups'))
    elif request.method == 'GET':
        form.name.data = group.name
        form.description.data = group.description
    return render_template('manager/group_form.html', title='Edit Group', form=form)

@bp.route('/groups/<int:id>/delete')
@login_required
@manager_required
def delete_group(id):
    group = UserGroup.query.get_or_404(id)
    # Optional: check if users are in group
    db.session.delete(group)
    db.session.commit()
    current_app.logger.info(f'Group deleted: {group.name} (ID: {id}) by {current_user.email}')
    flash('Group deleted.', 'success')
    return redirect(url_for('manager.groups'))

from werkzeug.utils import secure_filename
import os
from flask import current_app
from app.models import ModuleType, FileAsset, CourseModule
from app.manager.forms import ModuleForm

def handle_file_upload(file_storage):
    if not file_storage:
        return None
    
    filename = secure_filename(file_storage.filename)
    # Ensure unique filename
    base, ext = os.path.splitext(filename)
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    filename = f"{base}_{timestamp}{ext}"
    
    upload_folder = current_app.config['UPLOAD_FOLDER']
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)
        
    path = os.path.join(upload_folder, filename)
    file_storage.save(path)
    
    # Store relative path for URL generation
    relative_path = f"uploads/{filename}"
    
    asset = FileAsset(
        filename=filename,
        storage_path=relative_path,
        mime_type=file_storage.content_type,
        size=os.path.getsize(path),
        uploaded_by=current_user.id
    )
    db.session.add(asset)
    db.session.commit()
    return asset

@bp.route('/courses/<int:id>/modules')
@login_required
@manager_required
def course_modules(id):
    course = Course.query.get_or_404(id)
    return render_template('manager/modules.html', title=f'Modules: {course.title}', course=course)

@bp.route('/courses/<int:id>/modules/new', methods=['GET', 'POST'])
@login_required
@manager_required
def new_module(id):
    course = Course.query.get_or_404(id)
    form = ModuleForm()
    
    if form.validate_on_submit():
        module = CourseModule(
            course_id=course.id,
            title=form.title.data,
            type=form.type.data,
            estimated_minutes=form.estimated_minutes.data,
            content_url=form.content_url.data,
            body_html=form.body_html.data,
            is_required=form.is_required.data,
            order=course.modules.count() + 1
        )
        
        if form.file.data:
            asset = handle_file_upload(form.file.data)
            if asset:
                module.file_id = asset.id
        
        db.session.add(module)
        db.session.commit()
        current_app.logger.info(f'Module created: {module.title} (ID: {module.id}) for Course {course.id} by {current_user.email}')
        flash('Module created successfully.', 'success')
        return redirect(url_for('manager.course_modules', id=course.id))
        
    return render_template('manager/module_form.html', title='New Module', form=form, course=course)

@bp.route('/modules/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@manager_required
def edit_module(id):
    module = CourseModule.query.get_or_404(id)
    form = ModuleForm(obj=module)
    
    if form.validate_on_submit():
        module.title = form.title.data
        module.type = form.type.data
        module.estimated_minutes = form.estimated_minutes.data
        module.content_url = form.content_url.data
        module.body_html = form.body_html.data
        module.is_required = form.is_required.data
        
        if form.file.data:
            asset = handle_file_upload(form.file.data)
            if asset:
                module.file_id = asset.id
                
        db.session.commit()
        current_app.logger.info(f'Module updated: {module.title} (ID: {id}) by {current_user.email}')
        flash('Module updated successfully.', 'success')
        return redirect(url_for('manager.course_modules', id=module.course_id))
        
        return redirect(url_for('manager.course_modules', id=module.course_id))
        
    return render_template('manager/module_form.html', title='Edit Module', form=form, course=module.course, module=module)

@bp.route('/modules/<int:id>/delete-file', methods=['POST'])
@login_required
@manager_required
def delete_module_file(id):
    module = CourseModule.query.get_or_404(id)
    if module.file:
        # Optional: Delete actual file from disk
        # full_path = os.path.join(current_app.config['UPLOAD_FOLDER'], module.file.filename)
        # if os.path.exists(full_path):
        #    os.remove(full_path)
        
        # Remove DB association
        db.session.delete(module.file)
        module.file_id = None
        db.session.commit()
        flash('File deleted.', 'success')
    return redirect(url_for('manager.edit_module', id=module.id))

@bp.route('/modules/<int:id>/delete', methods=['POST'])
@login_required
@manager_required
def delete_module(id):
    module = CourseModule.query.get_or_404(id)
    course_id = module.course_id
    db.session.delete(module)
    db.session.commit()
    current_app.logger.info(f'Module deleted: {module.title} (ID: {id}) by {current_user.email}')
    flash('Module deleted.', 'success')
    return redirect(url_for('manager.course_modules', id=course_id))

@bp.route('/reports')
@login_required
@manager_required
def reports():
    return render_template('manager/reports.html', title='Reports')

@bp.route('/reports/export')
@login_required
@manager_required
def export_report():
    # Aggregate progress time per enrollment
    # We use a subquery or join for aggregation
    from sqlalchemy import func
    from app.models import ModuleProgress
    
    # Query: User, Course, Status, EnrolledDate, TotalTime(min)
    results = db.session.query(
        User.name.label('User'),
        Course.title.label('Course'),
        Enrollment.status.label('Status'),
        Enrollment.enrolled_at.label('Enrolled Date'),
        func.coalesce(func.sum(ModuleProgress.total_time_seconds), 0).label('total_seconds')
    ).join(Enrollment, User.id == Enrollment.user_id)\
     .join(Course, Enrollment.course_id == Course.id)\
     .outerjoin(ModuleProgress, Enrollment.id == ModuleProgress.enrollment_id)\
     .group_by(Enrollment.id, User.name, Course.title, Enrollment.status, Enrollment.enrolled_at)\
     .all()
    
    # Process for easy reading (seconds -> minutes)
    data = []
    for r in results:
        data.append({
            'User': r.User,
            'Course': r.Course,
            'Status': r.Status,
            'Enrolled Date': r[3], # Accessing by index for labeled columns might vary, checking simple object access if named tuple
            'Time Spent (Mins)': round(r.total_seconds / 60, 2)
        })

    df = pd.DataFrame(data)
    
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Enrollments', index=False)
    
    output.seek(0)
    filename = f"training_report_{datetime.now().strftime('%Y%m%d')}.xlsx"
    
    return send_file(output, download_name=filename, as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

# --- News Management ---
from app.manager.forms_news import NewsForm
from app.models import NewsItem, Notification
from flask_mail import Message
from app import mail

def send_async_email(subject, recipients, body):
    # This should be asynchronous in production (Celery/RQ)
    # For now, we try/except to avoid blocking if mail server is not configured
    try:
        if not recipients:
            return
            
        with current_app.app_context():
            msg = Message(subject, recipients=recipients)
            msg.body = body
            # msg.html = body_html # Optional
            mail.send(msg)
    except Exception as e:
        print(f"Email failed: {e}") 

@bp.route('/news')
@login_required
@manager_required
def news_list():
    news_items = NewsItem.query.order_by(NewsItem.created_at.desc()).all()
    return render_template('manager/news_list.html', title='Crypto News', news_items=news_items)

@bp.route('/news/new', methods=['GET', 'POST'])
@login_required
@manager_required
def new_news():
    form = NewsForm()
    if form.validate_on_submit():
        news = NewsItem(
            title=form.title.data,
            type=form.type.data,
            content_url=form.content_url.data,
            body_html=form.body_html.data,
            is_published=form.is_published.data,
            created_by_id=current_user.id
        )
        
        if form.file.data:
            asset = handle_file_upload(form.file.data)
            if asset:
                news.file_id = asset.id
        
        db.session.add(news)
        db.session.commit()
        current_app.logger.info(f'News item created: {news.title} (ID: {news.id}) by {current_user.email}')
        
        if news.is_published:
            # Notify all users
            users = User.query.all()
            for user in users:
                notification = Notification(
                    user_id=user.id,
                    title="New Crypto News Published",
                    message=f"New article: {news.title}",
                    link=url_for('staff.news_detail', id=news.id)
                )
                db.session.add(notification)
            
            # Send Email (Simplified)
            # recipients = [u.email for u in users if u.email]
            # send_async_email("New Crypto News: " + news.title, recipients, f"Check out the new update: {url_for('staff.news_detail', id=news.id, _external=True)}")
            
            db.session.commit()
            
        flash('News item created.', 'success')
        return redirect(url_for('manager.news_list'))
        
    return render_template('manager/news_form.html', title='New News Item', form=form)

@bp.route('/news/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@manager_required
def edit_news(id):
    news = NewsItem.query.get_or_404(id)
    form = NewsForm(obj=news)
    
    if form.validate_on_submit():
        news.title = form.title.data
        news.type = form.type.data
        news.content_url = form.content_url.data
        news.body_html = form.body_html.data
        news.is_published = form.is_published.data
        
        if form.file.data:
            asset = handle_file_upload(form.file.data)
            if asset:
                news.file_id = asset.id
                
        db.session.commit()
        current_app.logger.info(f'News item updated: {news.title} (ID: {id}) by {current_user.email}')
        flash('News updated.', 'success')
        return redirect(url_for('manager.news_list'))
        
    return render_template('manager/news_form.html', title='Edit News', form=form, news=news, module=news) # pass as module for file reuse if needed, or just news

@bp.route('/news/<int:id>/delete', methods=['POST'])
@login_required
@manager_required
def delete_news(id):
    news = NewsItem.query.get_or_404(id)
    db.session.delete(news)
    db.session.commit()
    current_app.logger.info(f'News item deleted: {news.title} (ID: {id}) by {current_user.email}')
    flash('News deleted.', 'success')
    return redirect(url_for('manager.news_list'))

@bp.route('/training-groups/create-ajax', methods=['POST'])
@login_required
@manager_required
def create_training_group_ajax():
    # print("Received AJAX request to create Training Group") # Debug
    data = request.get_json()
    if not data:
         return {'success': False, 'message': 'No data provided'}, 400
         
    name = data.get('name')
    description = data.get('description')
    
    if not name:
        return {'success': False, 'message': 'Name is required'}, 400
        
    # Check if exists
    if TrainingGroup.query.filter_by(name=name).first():
        return {'success': False, 'message': 'Group with this name already exists'}, 400
        
    try:
        group = TrainingGroup(name=name, description=description)
        db.session.add(group)
        db.session.commit()
        return {'success': True, 'id': group.id, 'name': group.name}
    except Exception as e:
        db.session.rollback()
        return {'success': False, 'message': str(e)}, 500

@bp.route('/reports/data/users')
@login_required
@manager_required
def reports_data_users():
    # Fetch detailed enrollment data
    results = db.session.query(
        User,
        Enrollment,
        Course,
        TrainingGroup,
        func.coalesce(func.sum(ModuleProgress.total_time_seconds), 0).label('total_seconds')
    ).join(Enrollment, User.id == Enrollment.user_id)\
     .join(Course, Enrollment.course_id == Course.id)\
     .outerjoin(TrainingGroup, Course.training_group_id == TrainingGroup.id)\
     .outerjoin(ModuleProgress, Enrollment.id == ModuleProgress.enrollment_id)\
     .group_by(Enrollment.id)\
     .all()
     
    data = []
    for user, enrollment, course, t_group, total_seconds in results:
        # Get User Groups
        user_groups = ", ".join([g.name for g in user.groups])
        
        # Calculate days to complete
        days_to_complete = None
        if enrollment.completed_at and enrollment.enrolled_at:
             delta = enrollment.completed_at - enrollment.enrolled_at
             days_to_complete = delta.days

        data.append({
            'user_name': user.name,
            'user_email': user.email,
            'user_groups': user_groups,
            'course_title': course.title,
            'training_group': t_group.name if t_group else 'None',
            'status': enrollment.status,
            'enrolled_date': enrollment.enrolled_at.strftime('%Y-%m-%d') if enrollment.enrolled_at else '',
            'completed_date': enrollment.completed_at.strftime('%Y-%m-%d') if enrollment.completed_at else '',
            'days_to_complete': days_to_complete,
            'time_spent_mins': round(total_seconds / 60, 2)
        })
        
    return {'data': data}

@bp.route('/reports/data/courses')
@login_required
@manager_required
def reports_data_courses():
    # Fetch course aggregate data
    courses = Course.query.all()
    data = []
    
    for course in courses:
        enrolled_count = course.enrollments.count()
        completed_count = course.enrollments.filter_by(status=EnrollmentStatus.COMPLETED.value).count()
        
        # Training Group
        t_group_name = course.training_group.name if course.training_group else 'None'
        
        # Visible User Groups
        visible_groups = ", ".join([g.name for g in course.visible_to_groups])

        data.append({
            'course_title': course.title,
            'training_group': t_group_name,
            'visible_groups': visible_groups,
            'created_at': course.created_at.strftime('%Y-%m-%d'),
            'status': course.status,
            'enrolled_count': enrolled_count,
            'completed_count': completed_count,
            'completion_rate': round((completed_count / enrolled_count * 100), 1) if enrolled_count > 0 else 0
        })
        
    return {'data': data}
