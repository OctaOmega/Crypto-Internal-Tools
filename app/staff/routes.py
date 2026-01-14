from flask import render_template, redirect, url_for, flash, abort, request
from flask_login import login_required, current_user
from app import db
from app.staff import bp
from app.models import Course, Enrollment, EnrollmentStatus, CourseModule, ModuleProgress, ProgressStatus, Tool, Notification
from app.decorators import staff_required
from app.staff.forms import ChangePasswordForm
from datetime import datetime
import io
import zipfile
import base64
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12
from flask import send_file
from app.email_utils import send_email
import jks
import hashlib
import os

def parse_cert_source(file_data, filename, password=None):
    """
    Parses a certificate source (PEM, PFX, JKS) and returns a list of available certs.
    Returns: {'type': 'single'|'multi', 'certs': [{'alias': '...', 'subject': '...'}], 'format': '...', 'data': ...}
    """
    filename_lower = filename.lower()
    
    try:
        if filename_lower.endswith('.jks') or filename_lower.endswith('.keystore'):
            # Use python-jks
            try:
                # helper to try password
                def load_store(pwd):
                     return jks.KeyStore.loads(file_data, pwd)
                
                keystore = None
                try:
                    keystore = load_store(password if password else '')
                except:
                     # Try common defaults if empty or failed? 
                     # python-jks usually needs correct password to decrypt proprietary format, 
                     # OR if it's JKS, it might read public certs without it? 
                     # Actually JKS integrity check needs password. Standard JKS is often 'changeit'.
                     # But if user provided none, and it failed, maybe try 'changeit'? 
                     # For now, just let it fail or rely on user input.
                     # But wait, sometimes users upload JKS without password for truststores.
                     # jks library raises error usually.
                     if not password:
                         # Try 'changeit' as fallback?
                         try: keystore = load_store('changeit')
                         except: pass
                     
                     if not keystore: raise

            except Exception as e:
                raise Exception(f"JKS Load Error: {str(e)}")

            aliases = []
            
            # Private Keys (usually have cert chains)
            for alias, pk in keystore.private_keys.items():
                # pk.cert_chain is a list of (type, data) tuples
                if pk.cert_chain:
                     # Parse first cert to get subject
                     cert = x509.load_der_x509_certificate(pk.cert_chain[0][1], default_backend())
                     aliases.append({'alias': alias, 'subject': cert.subject.rfc4514_string(), 'type': 'private_key'})
            
            # Trusted Certs
            for alias, c in keystore.certs.items():
                 cert = x509.load_der_x509_certificate(c.cert, default_backend())
                 aliases.append({'alias': alias, 'subject': cert.subject.rfc4514_string(), 'type': 'trusted_cert'})

            return {'type': 'multi', 'certs': aliases, 'format': 'jks', 'data': file_data}

        elif filename_lower.endswith('.p12') or filename_lower.endswith('.pfx'):
            try:
                p12 = pkcs12.load_key_and_certificates(
                    file_data,
                    password.encode() if password else None,
                    backend=default_backend()
                )
                certs = []
                if p12[1]: # Main cert
                    certs.append({'alias': 'Main Certificate', 'subject': p12[1].subject.rfc4514_string(), 'obj': p12[1]})
                if p12[2]: # Additional
                    for i, cert in enumerate(p12[2]):
                        certs.append({'alias': f'Additional Cert {i+1}', 'subject': cert.subject.rfc4514_string(), 'obj': cert})
                
                return {'type': 'multi', 'certs': certs, 'format': 'pfx', 'data': file_data}
            except Exception as e:
                raise Exception(f"PFX Load Error: {str(e)}")

        else:
            # Assume PEM/DER
            try:
                # Try PEM
                cert = x509.load_pem_x509_certificate(file_data, default_backend())
                return {'type': 'single', 'cert': cert, 'format': 'pem'}
            except:
                # Try DER
                try:
                    cert = x509.load_der_x509_certificate(file_data, default_backend())
                    return {'type': 'single', 'cert': cert, 'format': 'der'}
                except:
                     raise Exception("Could not parse as PEM or DER certificate")
    except Exception as e:
        raise e

def extract_cert_from_source(source_info, selection_alias=None, password=None):
    """
    Extracts the specific x509 certificate based on selection.
    """
    if source_info['format'] == 'jks':
        keystore = jks.KeyStore.loads(source_info['data'], password if password else '')
        # Try finding in private keys
        if selection_alias in keystore.private_keys:
             pk = keystore.private_keys[selection_alias]
             if pk.cert_chain:
                 return x509.load_der_x509_certificate(pk.cert_chain[0][1], default_backend())
        # Try finding in certs
        if selection_alias in keystore.certs:
             c = keystore.certs[selection_alias]
             return x509.load_der_x509_certificate(c.cert, default_backend())
        
        raise Exception(f"Alias {selection_alias} not found in JKS")

    elif source_info['format'] == 'pfx':
        # We re-parse or use cached objs. 
        # Since we can't easily pickle x509 objs across requests if we use stateless web, 
        # we might need to re-parse. For now assuming we re-parse.
        p12 = pkcs12.load_key_and_certificates(
            source_info['data'],
            password.encode() if password else None,
            default_backend()
        )
        if selection_alias == 'Main Certificate':
            return p12[1]
        elif selection_alias.startswith('Additional Cert '):
            idx = int(selection_alias.replace('Additional Cert ', '')) - 1
            return p12[2][idx]
        return None

    else:
        return source_info['cert']

def format_hex(data):
    """Formats bytes into a colon-separated hex string."""
    return ":".join(f"{b:02x}" for b in data)

def format_modulus(n):
    """Formats RSA modulus with newlines and colon separation."""
    hex_str = f"{n:x}"
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    
    # Split into pairs
    pairs = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
    
    # Group into lines of 16 pairs (like OpenSSL)
    lines = []
    for i in range(0, len(pairs), 16):
        lines.append(":".join(pairs[i:i+16]))
    
    return lines

def get_name_attributes(name):
    """Extracts and formats Name attributes (C, ST, L, O, OU, CN)."""
    attrs = []
    oid_map = {
        x509.NameOID.COUNTRY_NAME: 'C',
        x509.NameOID.STATE_OR_PROVINCE_NAME: 'ST',
        x509.NameOID.LOCALITY_NAME: 'L',
        x509.NameOID.ORGANIZATION_NAME: 'O',
        x509.NameOID.ORGANIZATIONAL_UNIT_NAME: 'OU',
        x509.NameOID.COMMON_NAME: 'CN',
        x509.NameOID.EMAIL_ADDRESS: 'Email'
    }
    
    for attr in name:
        label = oid_map.get(attr.oid, attr.oid._name)
        attrs.append({'label': label, 'value': attr.value})
    return attrs

def get_extensions(exts):
    """Extracts extension details."""
    details = []
    for ext in exts:
        ext_data = {
            'oid': ext.oid.dotted_string,
            'name': ext.oid._name,
            'critical': ext.critical,
            'value': str(ext.value) # Fallback
        }
        
        # Custom formatting for common extensions
        try:
            val = ext.value
            if isinstance(val, x509.SubjectAlternativeName):
                ext_data['value'] = ", ".join(d.value for d in val)
                ext_data['type'] = 'SAN'
            elif isinstance(val, x509.KeyUsage):
                usages = []
                if val.digital_signature: usages.append("Digital Signature")
                if val.content_commitment: usages.append("Content Commitment")
                if val.key_encipherment: usages.append("Key Encipherment")
                if val.data_encipherment: usages.append("Data Encipherment")
                if val.key_agreement: usages.append("Key Agreement")
                if val.key_cert_sign: usages.append("Certificate Sign")
                if val.crl_sign: usages.append("CRL Sign")
                if val.encipher_only: usages.append("Encipher Only")
                if val.decipher_only: usages.append("Decipher Only")
                ext_data['value'] = ", ".join(usages)
            elif isinstance(val, x509.BasicConstraints):
                ext_data['value'] = f"CA:{val.ca}, Path Length:{val.path_length}"
            elif isinstance(val, x509.ExtendedKeyUsage):
                 ext_data['value'] = ", ".join(u._name for u in val)
            elif isinstance(val, x509.AuthorityKeyIdentifier):
                 kid = format_hex(val.key_identifier) if val.key_identifier else "None"
                 ext_data['value'] = f"KeyID: {kid}"
            elif isinstance(val, x509.SubjectKeyIdentifier):
                 ext_data['value'] = format_hex(val.digest)
        except:
             pass 
             
        details.append(ext_data)
    return details

@bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.old_password.data):
            flash('Incorrect current password.', 'danger')
            return redirect(url_for('staff.change_password'))
            
        current_user.set_password(form.new_password.data)
        db.session.commit()
        flash('Your password has been updated.', 'success')
        return redirect(url_for('staff.dashboard'))
        
    return render_template('staff/change_password.html', title='Change Password', form=form)

@bp.route('/')
@bp.route('/dashboard')
@login_required
def dashboard():
    return redirect(url_for('staff.my_trainings'))

@bp.route('/notifications/delete/<int:id>', methods=['POST'])
@login_required
def delete_notification(id):
    notification = Notification.query.get_or_404(id)
    if notification.user_id != current_user.id:
        abort(403)
    
    db.session.delete(notification)
    db.session.commit()
    return redirect(url_for('staff.notifications'))

@bp.route('/notifications')
@login_required
def notifications():
    # Mark all shown as read on visit? Or just show them.
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    
    # Optional: Mark as read when viewing the list
    for n in notifications:
        if not n.is_read:
            n.is_read = True
    db.session.commit()
    
    return render_template('notifications.html', title='Notifications', notifications=notifications)

@bp.route('/my-trainings')
@login_required
def my_trainings():
    # Get active enrollments
    active_enrollments = current_user.enrollments.filter_by(status=EnrollmentStatus.ACTIVE.value).all()
    completed_enrollments = current_user.enrollments.filter_by(status=EnrollmentStatus.COMPLETED.value).all()
    
    return render_template('staff/dashboard.html', 
                           title='My Trainings', 
                           active=active_enrollments, 
                           completed=completed_enrollments,
                           today=datetime.utcnow())

@bp.route('/catalog')
@login_required
def catalog():
    query = request.args.get('q', '')
    sort_order = request.args.get('sort', 'title_asc')
    
    # Base query for published courses
    base_query = Course.query.filter_by(status='published')
    
    # Search Filter
    if query:
        base_query = base_query.filter(
            (Course.title.ilike(f'%{query}%')) | 
            (Course.description.ilike(f'%{query}%'))
        )
    
    # Sorting
    if sort_order == 'newest':
        base_query = base_query.order_by(Course.created_at.desc())
    elif sort_order == 'oldest':
        base_query = base_query.order_by(Course.created_at.asc())
    elif sort_order == 'title_desc':
        base_query = base_query.order_by(Course.title.desc())
    else: # title_asc default
        base_query = base_query.order_by(Course.title.asc())
        
    courses = base_query.all()
    
    # Existing enrollment check
    enrolled_ids = [e.course_id for e in current_user.enrollments.filter_by(status=EnrollmentStatus.ACTIVE.value).all()]
    completed_ids = [e.course_id for e in current_user.enrollments.filter_by(status=EnrollmentStatus.COMPLETED.value).all()]
    
    # Merge lists for checking "Open" state vs "Enroll"
    all_enrolled_ids = enrolled_ids + completed_ids
    
    return render_template('staff/catalog.html', title='Course Catalog', 
                           courses=courses, 
                           enrolled_ids=all_enrolled_ids,
                           query=query,
                           sort_order=sort_order)

@bp.route('/enroll/<int:course_id>', methods=['POST'])
@login_required
def enroll(course_id):
    course = Course.query.get_or_404(course_id)
    if course.status != 'published':
        flash('Course is not available.', 'danger')
        return redirect(url_for('staff.catalog'))
        
    # Check if already enrolled
    enrollment = Enrollment.query.filter_by(user_id=current_user.id, course_id=course_id).first()
    
    if not enrollment:
        enrollment = Enrollment(user_id=current_user.id, course_id=course_id)
        db.session.add(enrollment)
        db.session.commit()
        
        # Send Email
        send_email(
            subject=f'Enrollment Confirmation: {course.title}',
            recipients=[current_user.email],
            text_body=render_template('email/enrollment.txt', user=current_user, course=course),
            html_body=render_template('email/enrollment.html', user=current_user, course=course)
        )
        
        flash(f'You have enrolled in {course.title}', 'success')
    else:
        # If withdrawn, maybe re-activate? For now just say already enrolled
        if enrollment.status == EnrollmentStatus.WITHDRAWN.value:
            enrollment.status = EnrollmentStatus.ACTIVE.value
            db.session.commit()
            flash(f'You have re-enrolled in {course.title}', 'success')
        else:
            flash('You are already enrolled.', 'info')
        
    return redirect(url_for('staff.my_trainings'))

@bp.route('/course/<int:course_id>')
@login_required
def course_detail(course_id):
    enrollment = current_user.enrollments.filter_by(course_id=course_id).first_or_404()
    
    # Sync: Check if there are new modules added since enrollment or missing progress records
    existing_module_ids = [p.module_id for p in enrollment.progress_records.all()]
    all_modules = enrollment.course.modules.all()
    
    new_records = []
    for module in all_modules:
        if module.id not in existing_module_ids:
            progress = ModuleProgress(enrollment=enrollment, module_id=module.id, status=ProgressStatus.NOT_STARTED.value)
            db.session.add(progress)
            new_records.append(progress)
    
    if new_records:
        db.session.commit()
    
    # Needs re-query after commit to ensure relationships are loaded
    
    # Get first incomplete module or first module
    default_module = enrollment.progress_records.filter(ModuleProgress.status != ProgressStatus.COMPLETED.value).first()
    if not default_module:
         default_module = enrollment.progress_records.first()
         
    # Removed auto-redirect to allow "Start Course" option
    # if default_module:
    #    return redirect(url_for('staff.module_view', course_id=course_id, module_id=default_module.module_id))
    
    # Fallback if no modules
    # Fetch progress records ordered by module order
    progress_records = enrollment.progress_records.join(CourseModule).order_by(CourseModule.order).all()
    
    return render_template('staff/course_detail.html', title=enrollment.course.title, enrollment=enrollment, progress_records=progress_records)

@bp.route('/course/<int:course_id>/start', methods=['POST'])
@login_required
def start_course(course_id):
    enrollment = current_user.enrollments.filter_by(course_id=course_id).first_or_404()
    
    if not enrollment.started_at:
        enrollment.started_at = datetime.utcnow()
        db.session.commit()
        
    # Redirect to first module
    first_module = enrollment.course.modules.order_by(CourseModule.order).first()
    if first_module:
        return redirect(url_for('staff.module_view', course_id=course_id, module_id=first_module.id))
    
    return redirect(url_for('staff.course_detail', course_id=course_id))

@bp.route('/course/<int:course_id>/module/<int:module_id>')
@login_required
def module_view(course_id, module_id):
    enrollment = current_user.enrollments.filter_by(course_id=course_id).first_or_404()
    module = CourseModule.query.get_or_404(module_id)
    
    if module.course_id != course_id:
        abort(404)
        
    progress = ModuleProgress.query.filter_by(enrollment_id=enrollment.id, module_id=module_id).first()
    
    # Mark as in-progress if not started
    if progress.status == ProgressStatus.NOT_STARTED.value:
        progress.status = ProgressStatus.IN_PROGRESS.value
        progress.started_at = datetime.utcnow()
        db.session.commit()
        
    all_progress = enrollment.progress_records.join(CourseModule).order_by(CourseModule.order).all()
    
    return render_template('staff/module_view.html', 
                           title=module.title, 
                           course=enrollment.course, 
                           module=module, 
                           current_progress=progress,
                           all_progress=all_progress)

@bp.route('/tools')
@login_required
def tools():
    return render_template('staff/tools.html', title='Internal Tools')

# --- News Routes ---
from app.models import NewsItem

@bp.route('/news')
@login_required
def news():
    query = request.args.get('q', '')
    sort_order = request.args.get('sort', 'desc')
    
    base_query = NewsItem.query.filter_by(is_published=True)
    
    if query:
        base_query = base_query.filter(NewsItem.title.ilike(f'%{query}%'))
    
    if sort_order == 'asc':
        base_query = base_query.order_by(NewsItem.created_at.asc())
    else:
        base_query = base_query.order_by(NewsItem.created_at.desc())
        
    news_items = base_query.all()
    return render_template('staff/news_list.html', title='Crypto News', news_items=news_items, query=query, sort_order=sort_order)

@bp.route('/news/<int:id>')
@login_required
def news_detail(id):
    news = NewsItem.query.get_or_404(id)
    if not news.is_published:
        flash('This news item is not available.', 'danger')
        return redirect(url_for('staff.news'))
    return render_template('staff/news_detail.html', title=news.title, news=news)


@bp.route('/tools/csr', methods=['GET', 'POST'])
@login_required
def tool_csr():
    result = None
    error = None
    if request.method == 'POST':
        csr_data = request.form.get('csr_content')
        if csr_data:
            try:
                csr = x509.load_pem_x509_csr(csr_data.encode(), default_backend())
                
                # Public Key
                pub_key = csr.public_key()
                pub_numbers = pub_key.public_numbers()
                
                result = {
                    'subject': get_name_attributes(csr.subject),
                    'version': csr.version.name if hasattr(csr, 'version') else 'v1',
                    'signature_algorithm': csr.signature_algorithm_oid._name if hasattr(csr.signature_algorithm_oid, '_name') else str(csr.signature_algorithm_oid),
                    'public_key': {
                        'algorithm': 'RSA' if isinstance(pub_key, rsa.RSAPublicKey) else pub_key.__class__.__name__,
                        'length': pub_key.key_size,
                        'modulus': format_modulus(pub_numbers.n) if hasattr(pub_numbers, 'n') else None,
                        'exponent': pub_numbers.e if hasattr(pub_numbers, 'e') else None
                    },
                    'extensions': get_extensions(csr.extensions)
                }
            except Exception as e:
                error = f"Invalid CSR Data: {str(e)}"
    
    return render_template('staff/tool_csr.html', title='CSR Decoder', result=result, error=error)

@bp.route('/tools/x509', methods=['GET', 'POST'])
@login_required
def tool_x509():
    result = None
    error = None
    if request.method == 'POST':
        cert_data = request.form.get('cert_content')
        if cert_data:
            try:
                cert = x509.load_pem_x509_certificate(cert_data.encode(), default_backend())
                
                # Public Key
                pub_key = cert.public_key()
                pub_numbers = pub_key.public_numbers()
                
                # Fingerprints
                clean_bytes = cert.public_bytes(serialization.Encoding.DER) # For consistent hashing? Or hash the whole cert? 
                # Standard is hash the DER of the cert
                fingerprints = {
                    'md5': format_hex(cert.fingerprint(hashes.MD5())),
                    'sha1': format_hex(cert.fingerprint(hashes.SHA1())),
                    'sha256': format_hex(cert.fingerprint(hashes.SHA256()))
                }

                result = {
                    'version': f"{cert.version.value} ({hex(cert.version.value)})" if hasattr(cert.version, 'value') else str(cert.version.name),
                    'serial_number': f"{cert.serial_number} ({hex(cert.serial_number)})",
                    'signature_algorithm': cert.signature_algorithm_oid._name,
                    'not_valid_before': cert.not_valid_before,
                    'not_valid_after': cert.not_valid_after,
                    'issuer': get_name_attributes(cert.issuer),
                    'subject': get_name_attributes(cert.subject),
                    'fingerprints': fingerprints,
                    'public_key': {
                        'algorithm': 'RSA' if isinstance(pub_key, rsa.RSAPublicKey) else pub_key.__class__.__name__,
                        'length': pub_key.key_size,
                        'modulus': format_modulus(pub_numbers.n) if hasattr(pub_numbers, 'n') else None,
                        'exponent': f"{pub_numbers.e} ({hex(pub_numbers.e)})" if hasattr(pub_numbers, 'e') else None
                    },
                    'signature': format_modulus(int.from_bytes(cert.signature, 'big')),
                    'extensions': get_extensions(cert.extensions)
                }
            except Exception as e:
                 import traceback
                 traceback.print_exc()
                 error = f"Invalid Certificate Data: {str(e)}"
    
    return render_template('staff/tool_x509.html', title='Certificate Decoder', result=result, error=error)

@bp.route('/tools/csr-generator', methods=['GET', 'POST'])
@login_required
def tool_csr_generator():
    if request.method == 'POST':
        try:
            # Gather inputs
            cn = request.form.get('cn')
            org = request.form.get('org')
            ou = request.form.get('ou')
            city = request.form.get('city')
            state = request.form.get('state')
            country = request.form.get('country')
            password = request.form.get('password')
            sans_input = request.form.get('sans', '')
            
            if not cn:
                flash("Common Name (CN) is required", "danger")
                return render_template('staff/tool_csr_generator.html', title='CSR Generator')

            # Generate Key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            # Build Subject
            subject_attributes = [x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)]
            if org: subject_attributes.append(x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, org))
            if ou: subject_attributes.append(x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
            if city: subject_attributes.append(x509.NameAttribute(x509.NameOID.LOCALITY_NAME, city))
            if state: subject_attributes.append(x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, state))
            if country: subject_attributes.append(x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country))
            
            subject = x509.Name(subject_attributes)
            
            # Build Builder
            builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
            
            # SANs
            if sans_input:
                san_list = []
                for san in sans_input.split(','):
                    san = san.strip()
                    if san:
                         san_list.append(x509.DNSName(san))
                if san_list:
                    builder = builder.add_extension(
                        x509.SubjectAlternativeName(san_list),
                        critical=False
                    )

            # Sign
            csr = builder.sign(key, hashes.SHA256(), default_backend())

            # Export Key
            encryption = serialization.NoEncryption()
            if password:
                encryption = serialization.BestAvailableEncryption(password.encode())
            
            key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption
            )
            
            csr_pem = csr.public_bytes(serialization.Encoding.PEM)

            # Zip
            memory_file = io.BytesIO()
            with zipfile.ZipFile(memory_file, 'w') as zf:
                zf.writestr('private.key', key_pem)
                zf.writestr('request.csr', csr_pem)
            
            memory_file.seek(0)
            return send_file(
                memory_file,
                download_name=f'{cn}_csr_bundle.zip',
                as_attachment=True
            )

        except Exception as e:
            flash(f"Error generating CSR: {str(e)}", "danger")

    return render_template('staff/tool_csr_generator.html', title='CSR Generator')

@bp.route('/tools/pfx-split', methods=['GET', 'POST'])
@login_required
def tool_pfx_split():
    if request.method == 'POST':
        try:
            pfx_file = request.files.get('pfx_file')
            password = request.form.get('password')
            output_format = request.form.get('format', 'crt') # cer or crt
            custom_name = request.form.get('name')
            
            if not pfx_file:
                flash("PFX file is required", "danger")
                return render_template('staff/tool_pfx_split.html', title='Split PFX/P12')
                
            pfx_data = pfx_file.read()
            
            # Load PFX
            private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                pfx_data,
                password.encode() if password else None,
                backend=default_backend()
            )
            
            # Determine filenames
            if not custom_name:
                custom_name = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                # Sanitize filename
                custom_name = "".join(x for x in custom_name if x.isalnum() or x in "._- ")

            cert_ext = output_format
            
            # Prepare ZIP
            memory_file = io.BytesIO()
            with zipfile.ZipFile(memory_file, 'w') as zf:
                # Private Key
                if private_key:
                    key_pem = private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    zf.writestr(f'{custom_name}.key', key_pem)
                
                # Certificate
                if certificate:
                    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
                    zf.writestr(f'{custom_name}.{cert_ext}', cert_pem)
                    
                # Signers / Additional Certs
                signers_file = request.files.get('signers_file')
                if signers_file:
                    signers_data = signers_file.read()
                    zf.writestr('signers.pem', signers_data)
                elif additional_certificates:
                    # Also include bundled certs from PFX if any
                    chain_pem = b""
                    for cert in additional_certificates:
                         chain_pem += cert.public_bytes(serialization.Encoding.PEM)
                    zf.writestr('chain.pem', chain_pem)

            memory_file.seek(0)
            return send_file(
                memory_file,
                download_name=f'{custom_name}_split.zip',
                as_attachment=True
            )

        except Exception as e:
            flash(f"Error splitting PFX: {str(e)}", "danger")

    return render_template('staff/tool_pfx_split.html', title='Split PFX/P12')

@bp.route('/tools/jks-base64', methods=['GET', 'POST'])
@login_required
def tool_jks_base64():
    result = None
    if request.method == 'POST':
        jks_file = request.files.get('jks_file')
        if jks_file:
            try:
                file_data = jks_file.read()
                # mimic "cat JKS | base64 | tr -d '\n'"
                b64_data = base64.b64encode(file_data).decode('utf-8')
                result = b64_data
            except Exception as e:
                flash(f"Error converting file: {str(e)}", "danger")
    
    return render_template('staff/tool_jks_base64.html', title='JKS to Base64', result=result)
    
@bp.route('/tools/compare-certs', methods=['GET', 'POST'])
@login_required
def tool_compare_certs():
    result = None
    error = None
    selection_stage = False
    
    # We might need to store uploaded files temporarily if we are in "selection" stage
    # But files are lost after request. 
    # Solution: If Method is POST and 'action' is 'compare', we expect files selected.
    # If Method is POST and 'action' is 'analyze', we parse and if multi, show selection.
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        try:
            # File data might be in request.files OR we might have to cache it?
            # Standard pattern: User uploads, if disambiguation needed, we render page with hidden fields containing contents? 
            # Base64 encoding the file content into hidden fields is easiest for statelessness if files aren't huge.
            
            file_a_storage = request.files.get('file_a')
            file_b_storage = request.files.get('file_b')
            pass_a = request.form.get('password_a')
            pass_b = request.form.get('password_b')
            
            # Check if we are coming from selection stage (hidden content)
            content_a_b64 = request.form.get('content_a_b64')
            content_b_b64 = request.form.get('content_b_b64')
            
            data_a = None
            data_b = None
            name_a = request.form.get('name_a', 'File A')
            name_b = request.form.get('name_b', 'File B')

            if file_a_storage:
                data_a = file_a_storage.read()
                name_a = file_a_storage.filename
            elif content_a_b64:
                data_a = base64.b64decode(content_a_b64)
            
            if file_b_storage:
                data_b = file_b_storage.read()
                name_b = file_b_storage.filename
            elif content_b_b64:
                data_b = base64.b64decode(content_b_b64)
                
            if not data_a or not data_b:
                flash("Both files are required.", "danger")
                return render_template('staff/tool_compare_certs.html', title='Compare Certificates')

            # Parse Sources
            source_a = parse_cert_source(data_a, name_a, pass_a)
            source_b = parse_cert_source(data_b, name_b, pass_b)
            
            # Check if selection needed
            alias_a = request.form.get('alias_a')
            alias_b = request.form.get('alias_b')
            
            needs_selection_a = (source_a['type'] == 'multi' and not alias_a)
            needs_selection_b = (source_b['type'] == 'multi' and not alias_b)
            
            if needs_selection_a or needs_selection_b:
                selection_stage = True
                return render_template('staff/tool_compare_certs.html', 
                                       title='Compare Certificates', 
                                       selection_stage=True,
                                       source_a=source_a, source_b=source_b,
                                       pass_a=pass_a, pass_b=pass_b,
                                       name_a=name_a, name_b=name_b,
                                       content_a_b64=base64.b64encode(data_a).decode(),
                                       content_b_b64=base64.b64encode(data_b).decode())

            # Extract actual certs
            cert_a_obj = extract_cert_from_source(source_a, alias_a, pass_a)
            cert_b_obj = extract_cert_from_source(source_b, alias_b, pass_b)
            
            # Clean up temps
            # if 'temp_path' in source_a: os.remove(source_a['temp_path'])
            # if 'temp_path' in source_b: os.remove(source_b['temp_path'])

            # Compare
            # File Hashes
            hash_a = hashlib.sha256(data_a).hexdigest()
            hash_b = hashlib.sha256(data_b).hexdigest()
            
            # Extract Details using tool_x509 logic helper (we need to refactor logic or duplicate slightly)
            def get_details(cert):
                 pub = cert.public_key()
                 pub_n = pub.public_numbers()
                 return {
                     'subject': cert.subject.rfc4514_string(),
                     'issuer': cert.issuer.rfc4514_string(),
                     'serial': str(cert.serial_number),
                     'version': cert.version.name if hasattr(cert, 'version') else 'v1',
                     'not_before': cert.not_valid_before,
                     'not_after': cert.not_valid_after,
                     'fingerprint_sha1': binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode(),
                     'pub_alg': pub.__class__.__name__,
                     'pub_size': pub.key_size,
                     'pub_modulus_sha256': hashlib.sha256(str(pub_n.n).encode()).hexdigest() if hasattr(pub_n, 'n') else 'N/A',
                     'san': get_extensions(cert.extensions) # simplistic logic
                 }

            details_a = get_details(cert_a_obj)
            details_b = get_details(cert_b_obj)
            
            # Diff logic
            comparison = []
            keys = ['subject', 'issuer', 'serial', 'version', 'not_before', 'not_after', 'fingerprint_sha1', 'pub_alg', 'pub_size', 'pub_modulus_sha256']
            for k in keys:
                match = (details_a[k] == details_b[k])
                comparison.append({
                    'key': k,
                    'val_a': details_a[k],
                    'val_b': details_b[k],
                    'match': match
                })
            
            result = {
                'match_file_hash': (hash_a == hash_b),
                'hash_a': hash_a,
                'hash_b': hash_b,
                'comparison': comparison,
                'name_a': name_a,
                'name_b': name_b
            }
            
        except Exception as e:
            # import traceback
            # traceback.print_exc()
            error = f"Error processing certificates: {str(e)}"
            # Cleanup attempts
            # try:
            #     if 'source_a' in locals() and 'temp_path' in source_a: os.remove(source_a['temp_path'])
            #     if 'source_b' in locals() and 'temp_path' in source_b: os.remove(source_b['temp_path'])
            # except: pass

    return render_template('staff/tool_compare_certs.html', title='Compare Certificates', result=result, error=error)
