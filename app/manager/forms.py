from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, SubmitField, DateField
from wtforms.validators import DataRequired, Optional
from app.models import CourseStatus, TrainingGroup, UserGroup

class CourseForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description')
    due_date = DateField('Due Date', format='%Y-%m-%d', validators=[Optional()])
    status = SelectField('Status', choices=[
        (CourseStatus.DRAFT.value, 'Draft'),
        (CourseStatus.PUBLISHED.value, 'Published'),
        (CourseStatus.DISABLED.value, 'Disabled')
    ])
    training_group_id = SelectField('Training Group', coerce=int)
    submit = SubmitField('Save Course')

    def __init__(self, *args, **kwargs):
        super(CourseForm, self).__init__(*args, **kwargs)
        self.training_group_id.choices = [(g.id, g.name) for g in TrainingGroup.query.all()]

from flask_wtf.file import FileField, FileAllowed
from wtforms import IntegerField, SelectField, StringField, TextAreaField, BooleanField
from app.models import ModuleType

class ModuleForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    type = SelectField('Type', choices=[
        (ModuleType.RICH_TEXT.value, 'Rich Text / Instructions'),
        (ModuleType.VIDEO.value, 'Internal Video'),
        (ModuleType.YOUTUBE.value, 'YouTube Video'),
        (ModuleType.PDF.value, 'PDF Document'),
        (ModuleType.LINK.value, 'External Link')
    ], validators=[DataRequired()])
    estimated_minutes = IntegerField('Estimated Time (Minutes)', default=5, validators=[DataRequired()])
    content_url = StringField('Content URL (For YouTube or External Link)')
    file = FileField('File Upload (MP4 or PDF)', validators=[
        FileAllowed(['pdf', 'mp4', 'mov', 'webm'], 'PDFs and Videos only!')
    ])
    body_html = TextAreaField('Content Body (Rich Text)')
    is_required = BooleanField('Required Module', default=True)
    submit = SubmitField('Save Module')
