from flask import request, jsonify, render_template
from app.email_utils import send_email
from flask_login import login_required, current_user
from app import db
from app.api import bp
from app.models import ModuleProgress, ProgressStatus, Enrollment, Course, EnrollmentStatus, ActivityEvent
from datetime import datetime

@bp.route('/heartbeat', methods=['POST'])
@login_required
def heartbeat():
    data = request.get_json()
    module_id = data.get('module_id')
    enrollment_id = data.get('enrollment_id')
    
    if not module_id or not enrollment_id:
        return jsonify({'error': 'Missing data'}), 400
        
    progress = ModuleProgress.query.filter_by(enrollment_id=enrollment_id, module_id=module_id).first()
    
    # Security check: ensure enrollment belongs to current user
    if progress.enrollment.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
        
    if progress:
        progress.total_time_seconds += 30 # Assuming 30s interval
        progress.last_activity_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True})
        
    return jsonify({'error': 'Progress record not found'}), 404

@bp.route('/complete-module', methods=['POST'])
@login_required
def complete_module():
    data = request.get_json()
    module_id = data.get('module_id')
    enrollment_id = data.get('enrollment_id')
    
    progress = ModuleProgress.query.filter_by(enrollment_id=enrollment_id, module_id=module_id).first()
    
    if not progress or progress.enrollment.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
        
    progress.status = ProgressStatus.COMPLETED.value
    progress.completed_at = datetime.utcnow()
    progress.last_activity_at = datetime.utcnow()
    
    # Log Activity
    event = ActivityEvent(
        actor_id=current_user.id,
        course_id=progress.enrollment.course_id,
        module_id=module_id,
        type='module_completed'
    )
    db.session.add(event)
    
    # Check if all modules are completed for the enrollment
    enrollment = progress.enrollment
    all_modules_completed = not any(
        p.status != ProgressStatus.COMPLETED.value for p in enrollment.progress_records
    )
    
    if all_modules_completed:
        enrollment.status = EnrollmentStatus.COMPLETED.value
        enrollment.completed_at = datetime.utcnow()
        
        # Calculate total time
        total_seconds = sum(p.total_time_seconds for p in enrollment.progress_records)
        enrollment.total_time_seconds = total_seconds
        # Log Course Completion
        course_event = ActivityEvent(
            actor_id=current_user.id,
            course_id=enrollment.course_id,
            type='course_completed'
        )
        db.session.add(course_event)
        
        # Send Completion Email
        send_email(
            subject=f'Course Completed: {enrollment.course.title}',
            recipients=[current_user.email],
            text_body=render_template('email/completion.txt', user=current_user, course=enrollment.course),
            html_body=render_template('email/completion.html', user=current_user, course=enrollment.course)
        )
        
    db.session.commit()
    
    return jsonify({'success': True})
