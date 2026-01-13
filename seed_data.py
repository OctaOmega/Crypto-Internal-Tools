from app import create_app, db
from app.models import User, UserGroup, TrainingGroup, Course, CourseModule, Enrollment, Tool, UserRole, CourseStatus, ModuleType, EnrollmentStatus
from datetime import datetime
import random

app = create_app()

def seed():
    with app.app_context():
        print("Clearing database...")
        db.drop_all()
        db.create_all()

        print("Creating User Groups...")
        g1 = UserGroup(name='Tellers', description='Front-line banking staff')
        g2 = UserGroup(name='Advisors', description='Financial advisors and relationship managers')
        g3 = UserGroup(name='IT Support', description='Technical support staff')
        db.session.add_all([g1, g2, g3])
        db.session.commit()

        print("Creating Users...")
        # Admin
        admin = User(name='Administrator', email='admin@example.com', role=UserRole.ADMIN.value, status='active')
        admin.set_password('password')
        db.session.add(admin)
        db.session.commit()

        # Managers
        m1 = User(name='Manager Alice', email='alice@example.com', role=UserRole.MANAGER.value, status='active')
        m1.set_password('password')
        m2 = User(name='Manager Bob', email='bob@example.com', role=UserRole.MANAGER.value, status='active')
        m2.set_password('password')
        
        db.session.add_all([m1, m2])
        db.session.commit()

        # Staff
        staff_users = []
        for i in range(1, 11):
            s = User(name=f'Staff {i}', email=f'staff{i}@example.com', role=UserRole.STAFF.value, status='active')
            s.set_password('password')
            # Assign to random group
            group = random.choice([g1, g2, g3])
            s.groups.append(group)
            staff_users.append(s)
            
        db.session.add_all(staff_users)
        db.session.commit()

        print("Creating Training Groups...")
        tg1 = TrainingGroup(name='Compliance', description='Mandatory regulatory training')
        tg2 = TrainingGroup(name='Product Knowledge', description='Banking products and services')
        tg3 = TrainingGroup(name='Soft Skills', description='Customer service and communication')
        db.session.add_all([tg1, tg2, tg3])
        db.session.commit()

        print("Creating Courses...")
        c1 = Course(title='AML Essentials 2024', description='Anti-Money Laundering basics.', status=CourseStatus.PUBLISHED.value, training_group_id=tg1.id, created_by=m1.id)
        c2 = Course(title='Customer Service Excellence', description='How to handle difficult situations.', status=CourseStatus.PUBLISHED.value, training_group_id=tg3.id, created_by=m1.id)
        c3 = Course(title='New Chequing Accounts', description='Features of the 2024 accounts.', status=CourseStatus.PUBLISHED.value, training_group_id=tg2.id, created_by=m2.id)
        c4 = Course(title='Cybersecurity 101', description='Phishing and password safety.', status=CourseStatus.DRAFT.value, training_group_id=tg3.id, created_by=m2.id)
        c5 = Course(title='Advanced Lending', description='Mortgages and loans deep dive.', status=CourseStatus.PUBLISHED.value, training_group_id=tg2.id, created_by=m1.id)
        
        db.session.add_all([c1, c2, c3, c4, c5])
        db.session.commit()

        print("Creating Modules...")
        # Course 1: AML
        cm1_1 = CourseModule(course_id=c1.id, title='Introduction to AML', type=ModuleType.RICH_TEXT.value, order=1, estimated_minutes=5, body_html='<h3>Welcome to AML</h3><p>Money laundering is bad...</p>')
        cm1_2 = CourseModule(course_id=c1.id, title='Red Flags Video', type=ModuleType.YOUTUBE.value, order=2, estimated_minutes=15, content_url='https://www.youtube.com/watch?v=fakelink')
        cm1_3 = CourseModule(course_id=c1.id, title='Summary PDF', type=ModuleType.PDF.value, order=3, estimated_minutes=10, content_url='/static/dummy.pdf')
        
        # Course 2: Customer Service
        cm2_1 = CourseModule(course_id=c2.id, title='Empathy Map', type=ModuleType.RICH_TEXT.value, order=1, estimated_minutes=10, body_html='<p>Understand the customer...</p>')
        
        db.session.add_all([cm1_1, cm1_2, cm1_3, cm2_1])
        db.session.commit()

        print("Enrolling Staff...")
        # Enroll all staff in AML (Course 1)
        for s in staff_users:
            e = Enrollment(user_id=s.id, course_id=c1.id, enrolled_at=datetime.utcnow(), status=EnrollmentStatus.ACTIVE.value, assigned_by=m1.id)
            db.session.add(e)
            
        # Enroll random staff in Course 2
        for s in staff_users[:5]:
            e = Enrollment(user_id=s.id, course_id=c2.id, enrolled_at=datetime.utcnow(), status=EnrollmentStatus.ACTIVE.value, assigned_by=m2.id)
            db.session.add(e)

        db.session.commit()
        
        print("Creating Tools...")
        t1 = Tool(name='Interest Rate Calc', description='Calculate mortgage rates', url='https://calculator.net', icon='fa-calculator', created_by=m1.id)
        t2 = Tool(name='Staff Portal', description='HR and Benefits', url='https://hr.example.com', icon='fa-users', created_by=m1.id)
        db.session.add_all([t1, t2])
        db.session.commit()
        
        print("Done!")

if __name__ == '__main__':
    seed()
