from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, TextAreaField, SelectField, BooleanField, SubmitField
from wtforms.validators import DataRequired
from app.models import ModuleType

class NewsForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    type = SelectField('Type', choices=[
        (ModuleType.RICH_TEXT.value, 'Rich Text / Article'),
        (ModuleType.VIDEO.value, 'Internal Video'),
        (ModuleType.YOUTUBE.value, 'YouTube Video'),
        (ModuleType.PDF.value, 'PDF Document'),
        (ModuleType.LINK.value, 'External Link')
    ], validators=[DataRequired()])
    
    content_url = StringField('Content URL')
    file = FileField('File Upload (MP4 or PDF)', validators=[
        FileAllowed(['pdf', 'mp4', 'mov', 'webm'], 'PDFs and Videos only!')
    ])
    body_html = TextAreaField('Content Body (Rich Text)')
    is_published = BooleanField('Publish Immediately', default=True)
    submit = SubmitField('Save News Item')
