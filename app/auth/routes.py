from flask import render_template, redirect, url_for, flash, request, current_app
from urllib.parse import urlparse
from flask_login import login_user, logout_user, current_user
from app import db
from app.auth import bp
from app.auth.forms import LoginForm, ForgotPasswordForm, ResetPasswordForm
from app.models import User
from datetime import datetime, timedelta
from app.email_utils import send_email

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_manager():
            return redirect(url_for('manager.dashboard'))
        return redirect(url_for('staff.dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        # Check if locked
        if user and user.locked_until and user.locked_until > datetime.utcnow():
            flash('Account locked due to too many failed attempts. Try again later.', 'danger')
            current_app.logger.warning(f'Login attempt for locked account: {form.email.data}')
            return redirect(url_for('auth.login'))
            
        if user is None or not user.check_password(form.password.data):
            if user:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                    flash('Account locked for 15 minutes due to too many failed attempts.', 'danger')
                    current_app.logger.warning(f'Account locked due to failed logins: {user.email}')
                else:
                    flash('Invalid email or password', 'danger')
                    current_app.logger.info(f'Failed login attempt for user: {user.email}')
                db.session.commit()
            else:
                 flash('Invalid email or password', 'danger')
                 current_app.logger.warning(f'Failed login attempt for non-existent user: {form.email.data}')
            return redirect(url_for('auth.login'))
        
        # Success
        user.failed_login_attempts = 0
        user.locked_until = None
        db.session.commit()
        
        current_app.logger.info(f'Successful login for user: {user.email} (Role: {user.role})')
        
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            if user.is_manager():
                next_page = url_for('manager.dashboard')
            else:
                next_page = url_for('staff.dashboard')
        return redirect(next_page)
    
    return render_template('auth/login.html', title='Sign In', form=form)

@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('staff.dashboard')) # Default redirect
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.get_reset_password_token()
            send_email(
                subject='[Internal Training] Reset Your Password',
                recipients=[user.email],
                text_body=render_template('email/reset_password.txt', user=user, token=token),
                html_body=render_template('email/reset_password.html', user=user, token=token)
            )
        flash('Check your email for the instructions to reset your password', 'info')
        return redirect(url_for('auth.login'))
    return render_template('auth/forgot_password.html', title='Reset Password', form=form)

@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('staff.dashboard'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('auth.login'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', title='Reset Password', form=form)
