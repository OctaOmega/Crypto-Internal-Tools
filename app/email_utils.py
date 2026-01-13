from threading import Thread
from flask import current_app, render_template
from flask_mail import Message
from app import mail

def send_async_email(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
        except Exception as e:
            # In a real app, log provided exception
            print(f"Error sending email: {e}")

def send_email(subject, recipients, text_body, html_body, sender=None, attachments=None, sync=False):
    """
    Sends an email to the recipients.
    Checks if MAIL_SERVER is configured before attempting to send.
    """
    app = current_app._get_current_object()
    
    # Check if SMTP is configured
    if not app.config.get('MAIL_SERVER'):
        print("SMTP Credentials not found. Skipping email.")
        return

    if not sender:
        sender = app.config.get('MAIL_USERNAME') or 'noreply@example.com'

    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    
    if attachments:
        for attachment in attachments:
            msg.attach(*attachment)

    if sync:
        mail.send(msg)
    else:
        Thread(target=send_async_email, args=(app, msg)).start()
