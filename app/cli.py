import click
from flask.cli import AppGroup
from app import db
from app.models import Enrollment, EnrollmentStatus, Course
from app.email_utils import send_email
from flask import render_template
from datetime import datetime, timedelta

def register(app):
    email_cli = AppGroup('email')

    @email_cli.command('send-due-reminders')
    def send_due_reminders():
        """Sends reminders for courses due within the next 7 days."""
        print("Checking for due courses...")
        
        now = datetime.utcnow()
        upcoming_window = now + timedelta(days=7)
        
        # specific logic: Find active enrollments where course due date is between now and +7 days
        # Join Enrollment and Course
        active_enrollments = Enrollment.query.filter(
            Enrollment.status == EnrollmentStatus.ACTIVE.value
        ).join(Course).filter(
            Course.due_date != None,
            Course.due_date > now,
            Course.due_date <= upcoming_window
        ).all()
        
        count = 0
        for enrollment in active_enrollments:
            user = enrollment.student
            course = enrollment.course
            print(f"Sending reminder to {user.email} for course {course.title}")
            
            send_email(
                subject=f'Course Due Soon: {course.title}',
                recipients=[user.email],
                text_body=render_template('email/course_due.txt', user=user, course=course),
                html_body=render_template('email/course_due.html', user=user, course=course)
            )
            count += 1
            
        print(f"Sent {count} reminders.")

    app.cli.add_command(email_cli)
