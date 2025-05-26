from flask import Flask, request, jsonify, session, redirect, url_for, flash, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from flask_migrate import Migrate
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from bleach import clean
from datetime import datetime, timedelta
import os
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///notevault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True

print(f"Checking environment - MAIL_USERNAME: {os.environ.get('MAIL_USERNAME')}")
print(f"Checking environment - MAIL_PASSWORD set: {bool(os.environ.get('MAIL_PASSWORD'))}")
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') or 'notevault05@gmail.com'
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD') or 'ttuxrbbrsupocknv'
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME') or 'notevault05@gmail.com'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
    default_limits=["200 per day", "50 per hour"]
)
migrate = Migrate(app, db)

KEY_FILE = 'encryption_key.bin'
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'rb') as f:
        ENCRYPTION_KEY = f.read()
else:
    ENCRYPTION_KEY = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(ENCRYPTION_KEY)
cipher = Fernet(ENCRYPTION_KEY)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)
    email_notifications = db.Column(db.Boolean, default=True)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50))
    tags = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    collaborators = db.Column(db.String(200))
    reminder = db.Column(db.DateTime)
    view_token = db.Column(db.String(32), unique=True)
    is_unreadable = db.Column(db.Boolean, default=False)

class DraftNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50))
    tags = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    collaborators = db.Column(db.String(200))
    reminder = db.Column(db.DateTime)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(32), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=True)

def encrypt_content(content):
    return cipher.encrypt(content.encode()).decode()

def decrypt_content(encrypted_content):
    try:
        return cipher.decrypt(encrypted_content.encode()).decode()
    except InvalidToken:
        return None

def init_categories():
    default_categories = ["Personal", "Work", "Ideas", "To Do List", "Plans", "Expenditures", "Other"]
    for category_name in default_categories:
        if not Category.query.filter_by(name=category_name).first():
            category = Category(name=category_name)
            db.session.add(category)

def generate_view_token():
    return secrets.token_hex(16)

def generate_reset_token(user):
    token = secrets.token_hex(16)
    expires_at = datetime.utcnow() + timedelta(hours=1)
    reset_token = PasswordResetToken(user_id=user.id, token=token, expires_at=expires_at)
    db.session.add(reset_token)
    db.session.commit()
    return token

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    notifications = Notification.query.filter_by(user_id=session['user_id'], is_read=False).count()
    return render_template('front_page.html', unread_notifications=notifications)

@app.route('/view_notes')
def view_notes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    notes = Note.query.filter_by(user_id=session['user_id']).all()
    categories = Category.query.all()
    for note in notes:
        if note.is_unreadable:
            note.content = "This note cannot be decrypted due to a missing or changed encryption key."
        else:
            decrypted_content = decrypt_content(note.content)
            if decrypted_content is None:
                note.is_unreadable = True
                note.content = "This note cannot be decrypted due to a missing or changed encryption key."
                db.session.commit()
            else:
                note.content = decrypted_content
    notifications = Notification.query.filter_by(user_id=session['user_id'], is_read=False).count()
    return render_template('view_notes.html', notes=notes, categories=categories, unread_notifications=notifications)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = clean(request.form['username'])
        email = clean(request.form['email'])
        password = request.form['password']
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists.', 'error')
            return redirect(url_for('register'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = clean(request.form['username'])
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if not user:
            flash('Invalid credentials.', 'error')
            return render_template('login.html')

        if user.lockout_until and user.lockout_until > datetime.utcnow():
            remaining_time = (user.lockout_until - datetime.utcnow()).total_seconds() // 60
            flash(f'Account is locked due to too many failed attempts. Try again in {int(remaining_time)} minutes.', 'error')
            return render_template('login.html')

        if user and bcrypt.check_password_hash(user.password, password):
            user.failed_attempts = 0
            user.lockout_until = None
            db.session.commit()
            session['user_id'] = user.id
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))

        user.failed_attempts += 1
        if user.failed_attempts >= 5:
            user.lockout_until = datetime.utcnow() + timedelta(minutes=15)
            flash('Too many failed attempts. Account locked for 15 minutes.', 'error')
        else:
            flash('Invalid credentials.', 'error')
        db.session.commit()
        return render_template('login.html')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = clean(request.form['username'])
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('forgot_password'))
        session['reset_user_id'] = user.id
        return redirect(url_for('verify_email'))
    return render_template('forgot_password.html')

@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    if 'reset_user_id' not in session:
        flash('Invalid password reset request.', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['reset_user_id'])
    if not user:
        flash('User not found.', 'error')
        session.pop('reset_user_id', None)
        return redirect(url_for('login'))

    if request.method == 'POST':
        email = clean(request.form['email'])
        if email != user.email:
            flash('Email does not match the registered email.', 'error')
            return redirect(url_for('verify_email'))

        if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
            flash('Email service is not configured. Please contact support.', 'error')
            return redirect(url_for('verify_email'))

        token = generate_reset_token(user)
        reset_link = url_for('reset_password', token=token, _external=True)

        msg = Message('Password Reset Request - NoteVault', recipients=[user.email])
        msg.body = f"""
        Hello {user.username},

        You have requested to reset your password for NoteVault. Click the link below to reset your password:

        {reset_link}

        This link will expire in 1 hour. If you did not request a password reset, please ignore this email.

        Best,
        The NoteVault Team
        """
        try:
            mail.send(msg)
            flash('A password reset link has been sent to your email.', 'success')
            session.pop('reset_user_id', None)
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error sending email: {str(e)}', 'error')
            return redirect(url_for('verify_email'))

    return render_template('verify_email.html', username=user.username)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    if not reset_token:
        flash('Invalid or expired reset token.', 'error')
        return redirect(url_for('login'))

    if datetime.utcnow() > reset_token.expires_at:
        flash('This reset token has expired.', 'error')
        db.session.delete(reset_token)
        db.session.commit()
        return redirect(url_for('login'))

    user = User.query.get(reset_token.user_id)
    if not user:
        flash('User not found.', 'error')
        db.session.delete(reset_token)
        db.session.commit()
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not password or not confirm_password:
            flash('Both password fields are required.', 'error')
            return render_template('reset_password.html', token=token)

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)

        if len(password) < 8 or not any(c.isupper() for c in password) or not any(c in '!@#$%^&*(),.?":{}|<>]' for c in password) or not any(c.isdigit() for c in password):
            flash('Password must be at least 8 characters long and include 1 capital alphabet, 1 special character, and 1 numeric character.', 'error')
            return render_template('reset_password.html', token=token)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user.password = hashed_password
        db.session.delete(reset_token)
        db.session.commit()
        flash('Password reset successfully! Please log in with your new password.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/note/create', methods=['GET', 'POST'])
def create_note():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    categories = Category.query.all()
    if request.method == 'POST':
        title = clean(request.form['title'])
        content = clean(request.form['content'])
        
        max_length = 20000
        if len(content) > max_length:
            content = content[:max_length]
            flash('Content truncated to 20,000 characters.', 'warning')

        category = clean(request.form.get('category', ''))
        tags = clean(request.form.get('tags', ''))
        collaborators_input = clean(request.form.get('collaborators', ''))
        reminder = request.form.get('reminder', '')

        collaborators_list = []
        if collaborators_input:
            collaborators_list = [collab.strip() for collab in collaborators_input.split(',') if collab.strip()]
            current_user = User.query.get(session['user_id'])
            for collab in collaborators_list:
                if collab == current_user.username:
                    flash(f'You cannot add yourself as a collaborator.', 'error')
                    draft = DraftNote(
                        title=title,
                        content=content,
                        category=category,
                        tags=tags,
                        collaborators=collaborators_input,
                        reminder=datetime.strptime(reminder, '%Y-%m-%dT%H:%M') if reminder else None,
                        user_id=session['user_id']
                    )
                    db.session.add(draft)
                    db.session.commit()
                    notification = Notification(
                        user_id=session['user_id'],
                        message=f"Note '{title}' failed to save due to invalid collaborator. It has been saved as a draft.",
                        note_id=None
                    )
                    db.session.add(notification)
                    db.session.commit()
                    return render_template('create_note.html', 
                                         categories=categories,
                                         title=title,
                                         content=content,
                                         category=category,
                                         tags=tags,
                                         collaborators=collaborators_input,
                                         reminder=reminder)
                collaborator = User.query.filter_by(username=collab).first()
                if not collaborator:
                    flash(f"Collaborator '{collab}' does not exist.", 'error')
                    draft = DraftNote(
                        title=title,
                        content=content,
                        category=category,
                        tags=tags,
                        collaborators=collaborators_input,
                        reminder=datetime.strptime(reminder, '%Y-%m-%dT%H:%M') if reminder else None,
                        user_id=session['user_id']
                    )
                    db.session.add(draft)
                    db.session.commit()
                    notification = Notification(
                        user_id=session['user_id'],
                        message=f"Note '{title}' failed to save due to invalid collaborator. It has been saved as a draft.",
                        note_id=None
                    )
                    db.session.add(notification)
                    db.session.commit()
                    return render_template('create_note.html', 
                                         categories=categories,
                                         title=title,
                                         content=content,
                                         category=category,
                                         tags=tags,
                                         collaborators=collaborators_input,
                                         reminder=reminder)
            collaborators = ','.join(collaborators_list)
        else:
            collaborators = ''

        try:
            encrypted_content = encrypt_content(content)
            note = Note(
                title=title,
                content=encrypted_content,
                category=category,
                tags=tags,
                collaborators=collaborators,
                reminder=datetime.strptime(reminder, '%Y-%m-%dT%H:%M') if reminder else None,
                user_id=session['user_id'],
                view_token=generate_view_token(),
                is_unreadable=False
            )
            db.session.add(note)
            db.session.commit()

            if collaborators:
                for collab in collaborators_list:
                    collaborator = User.query.filter_by(username=collab).first()
                    notification = Notification(
                        user_id=collaborator.id,
                        message=f"{current_user.username} added you as a collaborator on note: {title}",
                        note_id=note.id
                    )
                    db.session.add(notification)
                db.session.commit()

            flash('Note created successfully!', 'success')
            return redirect(url_for('view_note', note_id=note.id))
        except Exception as e:
            db.session.rollback()
            draft = DraftNote(
                title=title,
                content=content,
                category=category,
                tags=tags,
                collaborators=collaborators_input,
                reminder=datetime.strptime(reminder, '%Y-%m-%dT%H:%M') if reminder else None,
                user_id=session['user_id']
            )
            db.session.add(draft)
            db.session.commit()
            notification = Notification(
                user_id=session['user_id'],
                message=f"Note '{title}' failed to save due to an unforeseen error. It has been saved as a draft.",
                note_id=None
            )
            db.session.add(notification)
            db.session.commit()
            flash(f'Failed to create note: {str(e)}. Saved as draft.', 'error')
            return render_template('create_note.html', 
                                 categories=categories,
                                 title=title,
                                 content=content,
                                 category=category,
                                 tags=tags,
                                 collaborators=collaborators_input,
                                 reminder=reminder)
    notifications = Notification.query.filter_by(user_id=session['user_id'], is_read=False).count()
    return render_template('create_note.html', categories=categories, unread_notifications=notifications)

@app.route('/draft/create', methods=['POST'])
def create_draft():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    title = clean(request.form.get('title', ''))
    content = clean(request.form.get('content', ''))
    category = clean(request.form.get('category', ''))
    tags = clean(request.form.get('tags', ''))
    collaborators = clean(request.form.get('collaborators', ''))
    reminder = request.form.get('reminder', '')

    if not title or not content:
        return jsonify({'success': False, 'message': 'Title and content are required.'}), 400

    max_length = 20000
    if len(content) > max_length:
        content = content[:max_length]

    draft = DraftNote(
        title=title,
        content=content,
        category=category,
        tags=tags,
        collaborators=collaborators,
        reminder=datetime.strptime(reminder, '%Y-%m-%dT%H:%M') if reminder else None,
        user_id=session['user_id']
    )
    db.session.add(draft)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Draft saved successfully!'})

@app.route('/drafts')
def view_drafts():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    drafts = DraftNote.query.filter_by(user_id=session['user_id']).all()
    # Preprocess draft content for display (truncate to 100 characters)
    for draft in drafts:
        if len(draft.content) > 100:
            draft.display_content = draft.content[:100] + '...'
        else:
            draft.display_content = draft.content
    notifications = Notification.query.filter_by(user_id=session['user_id'], is_read=False).count()
    return render_template('view_drafts.html', drafts=drafts, unread_notifications=notifications)

@app.route('/draft/<int:draft_id>/save', methods=['POST'])
def save_draft_as_note(draft_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    draft = DraftNote.query.get_or_404(draft_id)
    if draft.user_id != session['user_id']:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('view_drafts'))

    collaborators_list = []
    if draft.collaborators:
        collaborators_list = [collab.strip() for collab in draft.collaborators.split(',') if collab.strip()]
        current_user = User.query.get(session['user_id'])
        for collab in collaborators_list:
            if collab == current_user.username:
                flash('You cannot add yourself as a collaborator.', 'error')
                return redirect(url_for('view_drafts'))
            collaborator = User.query.filter_by(username=collab).first()
            if not collaborator:
                flash(f"Collaborator '{collab}' does not exist.", 'error')
                return redirect(url_for('view_drafts'))
        collaborators = ','.join(collaborators_list)
    else:
        collaborators = ''

    encrypted_content = encrypt_content(draft.content)
    note = Note(
        title=draft.title,
        content=encrypted_content,
        category=draft.category,
        tags=draft.tags,
        collaborators=collaborators,
        reminder=draft.reminder,
        user_id=session['user_id'],
        view_token=generate_view_token(),
        is_unreadable=False
    )
    db.session.add(note)
    db.session.delete(draft)
    db.session.commit()

    if collaborators:
        for collab in collaborators_list:
            collaborator = User.query.filter_by(username=collab).first()
            notification = Notification(
                user_id=collaborator.id,
                message=f"{current_user.username} added you as a collaborator on note: {draft.title}",
                note_id=note.id
            )
            db.session.add(notification)
        db.session.commit()

    flash('Draft saved as a note successfully!', 'success')
    return redirect(url_for('view_note', note_id=note.id))

@app.route('/draft/<int:draft_id>/edit', methods=['GET', 'POST'])
def edit_draft(draft_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    draft = DraftNote.query.get_or_404(draft_id)
    if draft.user_id != session['user_id']:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('view_drafts'))
    categories = Category.query.all()
    if request.method == 'POST':
        draft.title = clean(request.form['title'])
        draft.content = clean(request.form['content'])
        max_length = 20000
        if len(draft.content) > max_length:
            draft.content = draft.content[:max_length]
            flash('Content truncated to 20,000 characters.', 'warning')
        draft.category = clean(request.form.get('category', ''))
        draft.tags = clean(request.form.get('tags', ''))
        draft.collaborators = clean(request.form.get('collaborators', ''))
        reminder = request.form.get('reminder', '')
        draft.reminder = datetime.strptime(reminder, '%Y-%m-%dT%H:%M') if reminder else None
        db.session.commit()
        flash('Draft updated successfully!', 'success')
        return redirect(url_for('view_drafts'))
    notifications = Notification.query.filter_by(user_id=session['user_id'], is_read=False).count()
    return render_template('edit_draft.html', draft=draft, categories=categories, unread_notifications=notifications)

@app.route('/draft/<int:draft_id>/delete', methods=['POST'])
def delete_draft(draft_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    draft = DraftNote.query.get_or_404(draft_id)
    if draft.user_id != session['user_id']:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('view_drafts'))
    db.session.delete(draft)
    db.session.commit()
    flash('Draft deleted successfully!', 'success')
    return redirect(url_for('view_drafts'))

@app.route('/draft/<int:draft_id>/share', methods=['POST'])
def share_draft(draft_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    draft = DraftNote.query.get_or_404(draft_id)
    if draft.user_id != session['user_id']:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('view_drafts'))
    if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
        flash('Email sharing is not configured.', 'error')
        return redirect(url_for('view_drafts'))
    recipient_email = clean(request.form['email'])
    msg = Message('Shared Draft from NoteVault', recipients=[recipient_email])
    msg.body = f"Draft Title: {draft.title}\n\nContent: {draft.content}\n\nNote: This is a draft and not yet a published note."
    try:
        mail.send(msg)
        flash('Draft shared successfully!', 'success')
    except Exception as e:
        flash(f'Error sharing draft: {str(e)}', 'error')
    return redirect(url_for('view_drafts'))

@app.route('/draft/<int:draft_id>/add_collaborator', methods=['POST'])
def add_collaborator_to_draft(draft_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    draft = DraftNote.query.get_or_404(draft_id)
    if draft.user_id != session['user_id']:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('view_drafts'))
    collaborator_username = clean(request.form['collaborator'])
    current_user = User.query.get(session['user_id'])
    if collaborator_username == current_user.username:
        flash('You cannot add yourself as a collaborator.', 'error')
        return redirect(url_for('view_drafts'))
    collaborator = User.query.filter_by(username=collaborator_username).first()
    if not collaborator:
        flash(f"Collaborator '{collaborator_username}' does not exist.", 'error')
        return redirect(url_for('view_drafts'))
    current_collaborators = draft.collaborators.split(',') if draft.collaborators else []
    current_collaborators = [collab.strip() for collab in current_collaborators if collab.strip()]
    if collaborator_username in current_collaborators:
        flash(f"'{collaborator_username}' is already a collaborator.", 'info')
        return redirect(url_for('view_drafts'))
    current_collaborators.append(collaborator_username)
    draft.collaborators = ','.join(current_collaborators)
    db.session.commit()
    flash(f"Collaborator '{collaborator_username}' added to draft.", 'success')
    return redirect(url_for('view_drafts'))

@app.route('/note/<int:note_id>')
def view_note(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    note = Note.query.get_or_404(note_id)
    current_user = User.query.get(session['user_id'])
    collaborators = note.collaborators.split(',') if note.collaborators else []
    if note.user_id != session['user_id'] and current_user.username not in collaborators:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('index'))
    if note.is_unreadable:
        note.content = "This note cannot be decrypted due to a missing or changed encryption key."
    else:
        decrypted_content = decrypt_content(note.content)
        if decrypted_content is None:
            note.is_unreadable = True
            note.content = "This note cannot be decrypted due to a missing or changed encryption key."
            db.session.commit()
        else:
            note.content = decrypted_content
    notifications = Notification.query.filter_by(user_id=session['user_id'], is_read=False).count()
    return render_template('view_note.html', note=note, unread_notifications=notifications)

@app.route('/view_only/<token>')
def view_only(token):
    note = Note.query.filter_by(view_token=token).first_or_404()
    if note.is_unreadable:
        note.content = "This note cannot be decrypted due to a missing or changed encryption key."
    else:
        decrypted_content = decrypt_content(note.content)
        if decrypted_content is None:
            note.is_unreadable = True
            note.content = "This note cannot be decrypted due to a missing or changed encryption key."
            db.session.commit()
        else:
            note.content = decrypted_content
    return render_template('view_only.html', note=note)

@app.route('/note/<int:note_id>/edit', methods=['GET', 'POST'])
def edit_note(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    note = Note.query.get_or_404(note_id)
    current_user = User.query.get(session['user_id'])
    collaborators = note.collaborators.split(',') if note.collaborators else []
    if note.user_id != session['user_id'] and current_user.username not in collaborators:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('index'))
    categories = Category.query.all()
    if request.method == 'POST':
        title = clean(request.form['title'])
        content = clean(request.form['content'])
        
        max_length = 20000
        if len(content) > max_length:
            content = content[:max_length]
            flash('Content truncated to 20,000 characters.', 'warning')

        collaborators_input = clean(request.form.get('collaborators', ''))
        category = clean(request.form.get('category', ''))
        tags = clean(request.form.get('tags', ''))
        reminder = request.form.get('reminder', '')
        
        if collaborators_input:
            new_collaborators_list = [collab.strip() for collab in collaborators_input.split(',') if collab.strip()]
            if current_user.username in collaborators and current_user.username not in new_collaborators_list:
                flash('You cannot remove yourself as a collaborator.', 'error')
                note.title = title
                note.content = content
                note.category = category
                note.tags = tags
                note.collaborators = collaborators_input
                note.reminder = datetime.strptime(reminder, '%Y-%m-%dT%H:%M') if reminder else None
                return render_template('edit_note.html', 
                                     note=note,
                                     categories=categories,
                                     category=category)
            
            for collab in new_collaborators_list:
                if collab == current_user.username and collab not in collaborators:
                    flash(f'You cannot add yourself as a collaborator.', 'error')
                    note.title = title
                    note.content = content
                    note.category = category
                    note.tags = tags
                    note.collaborators = collaborators_input
                    note.reminder = datetime.strptime(reminder, '%Y-%m-%dT%H:%M') if reminder else None
                    return render_template('edit_note.html', 
                                         note=note,
                                         categories=categories,
                                         category=category)
                collaborator = User.query.filter_by(username=collab).first()
                if not collaborator:
                    flash(f"Collaborator '{collab}' does not exist.", 'error')
                    note.title = title
                    note.content = content
                    note.category = category
                    note.tags = tags
                    note.collaborators = collaborators_input
                    note.reminder = datetime.strptime(reminder, '%Y-%m-%dT%H:%M') if reminder else None
                    return render_template('edit_note.html', 
                                         note=note,
                                         categories=categories,
                                         category=category)
                if collab not in collaborators:
                    notification = Notification(
                        user_id=collaborator.id,
                        message=f"{current_user.username} added you as a collaborator on note: {title}",
                        note_id=note_id
                    )
                    db.session.add(notification)
            note.collaborators = ','.join(new_collaborators_list)
        else:
            if current_user.username in collaborators:
                flash('You cannot remove yourself as a collaborator.', 'error')
                note.title = title
                note.content = content
                note.category = category
                note.tags = tags
                note.collaborators = note.collaborators
                note.reminder = datetime.strptime(reminder, '%Y-%m-%dT%H:%M') if reminder else None
                return render_template('edit_note.html', 
                                     note=note,
                                     categories=categories,
                                     category=category)
            note.collaborators = ''

        note.title = title
        note.content = encrypt_content(content)
        note.category = category
        note.tags = tags
        note.reminder = datetime.strptime(reminder, '%Y-%m-%dT%H:%M') if reminder else None
        note.is_unreadable = False
        db.session.commit()
        flash('Note updated successfully!', 'success')
        return redirect(url_for('view_note', note_id=note.id))
    if note.is_unreadable:
        note.content = "This note cannot be decrypted due to a missing or changed encryption key."
    else:
        decrypted_content = decrypt_content(note.content)
        if decrypted_content is None:
            note.is_unreadable = True
            note.content = "This note cannot be decrypted due to a missing or changed encryption key."
            db.session.commit()
        else:
            note.content = decrypted_content
    notifications = Notification.query.filter_by(user_id=session['user_id'], is_read=False).count()
    return render_template('edit_note.html', note=note, categories=categories, unread_notifications=notifications)

@app.route('/note/<int:note_id>/delete', methods=['POST'])
def delete_note(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    note = Note.query.get_or_404(note_id)
    current_user = User.query.get(session['user_id'])
    if note.user_id != current_user.id:
        flash('You do not have permission to delete this note.', 'error')
        return redirect(url_for('view_note', note_id=note.id))
    db.session.delete(note)
    db.session.commit()
    flash('Note deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/note/<int:note_id>/share', methods=['POST'])
def share_note(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    note = Note.query.get_or_404(note_id)
    if note.user_id != session['user_id']:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('view_note', note_id=note.id))
    if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
        flash('Email sharing is not configured. Please set MAIL_USERNAME and MAIL_PASSWORD environment variables.', 'error')
        return redirect(url_for('view_note', note_id=note.id))
    recipient_email = clean(request.form['email'])
    user = User.query.filter_by(email=recipient_email).first()
    if user and user.username not in (note.collaborators.split(',') if note.collaborators else []):
        note.collaborators = f"{note.collaborators},{user.username}" if note.collaborators else user.username
        notification = Notification(
            user_id=user.id,
            message=f"{User.query.get(session['user_id']).username} added you as a collaborator on note: {note.title}",
            note_id=note.id
        )
        db.session.add(notification)
        db.session.commit()
        if user.email_notifications:
            msg = Message('Collaboration Invitation - NoteVault', recipients=[user.email])
            msg.body = f"""
            Hello {user.username},

            {User.query.get(session['user_id']).username} has added you as a collaborator for the note titled "{note.title}".
            You can now view and edit this note after logging in at: {url_for('view_note', note_id=note.id, _external=True)}

            Best,
            The NoteVault Team
            """
            try:
                mail.send(msg)
                flash(f'Notification sent to {user.username}. They are now a collaborator.', 'success')
            except Exception as e:
                flash(f'Error sending email notification to {user.username}: {str(e)}', 'error')
        else:
            flash(f'{user.username} added as a collaborator. They have email notifications disabled.', 'info')
    view_link = url_for('view_only', token=note.view_token, _external=True)
    if note.is_unreadable:
        note_content = "This note cannot be decrypted due to a missing or changed encryption key."
    else:
        decrypted_content = decrypt_content(note.content)
        if decrypted_content is None:
            note.is_unreadable = True
            note_content = "This note cannot be decrypted due to a missing or changed encryption key."
            db.session.commit()
        else:
            note_content = decrypted_content
    msg = Message('Shared Note from NoteVault', recipients=[recipient_email])
    msg.body = f"Note Title: {note.title}\n\nContent: {note_content}\n\n"
    if user:
        msg.body += f"You are a collaborator and can edit this note after logging in at: {url_for('view_note', note_id=note.id, _external=True)}\n"
    else:
        msg.body += f"View the note here (view-only): {view_link}\nTo edit this note, please register at NoteVault and ask the owner to add you as a collaborator.\n"
    try:
        mail.send(msg)
        flash('Note shared successfully!', 'success')
    except Exception as e:
        flash(f'Error sharing note: {str(e)}', 'error')
    return redirect(url_for('view_note', note_id=note.id))

@app.route('/notifications')
def notifications():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    notifications = Notification.query.filter_by(user_id=session['user_id']).order_by(Notification.created_at.desc()).all()
    unread_count = Notification.query.filter_by(user_id=session['user_id'], is_read=False).count()
    return render_template('notifications.html', notifications=notifications, unread_notifications=unread_count)

@app.route('/notification/<int:notification_id>/mark_read', methods=['POST'])
def mark_notification_read(notification_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != session['user_id']:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('notifications'))
    notification.is_read = True
    db.session.commit()
    flash('Notification marked as read.', 'success')
    return redirect(url_for('notifications'))

@app.route('/notification/<int:notification_id>/delete', methods=['POST'])
def delete_notification(notification_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != session['user_id']:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('notifications'))
    db.session.delete(notification)
    db.session.commit()
    flash('Notification deleted.', 'success')
    return redirect(url_for('notifications'))

@app.route('/notifications/clear', methods=['POST'])
def clear_notifications():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    Notification.query.filter_by(user_id=session['user_id']).delete()
    db.session.commit()
    flash('All notifications cleared.', 'success')
    return redirect(url_for('notifications'))

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        if 'email_notifications' in request.form:
            user.email_notifications = 'email_notifications' in request.form and request.form['email_notifications'] == 'on'
            db.session.commit()
            flash('Notification preferences updated.', 'success')
        elif 'new_password' in request.form:
            new_password = request.form['new_password']
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long.', 'error')
            else:
                user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                db.session.commit()
                flash('Password updated successfully.', 'success')
        elif 'verify_password' in request.form:
            password = request.form['password']
            if bcrypt.check_password_hash(user.password, password):
                return jsonify({'success': True})
            else:
                return jsonify({'success': False, 'error': 'Incorrect password'})
        elif 'delete_account' in request.form and 'confirm_delete' in request.form:
            try:
                Note.query.filter_by(user_id=user.id).delete()
                Notification.query.filter_by(user_id=user.id).delete()
                PasswordResetToken.query.filter_by(user_id=user.id).delete()
                db.session.delete(user)
                db.session.commit()
                session.pop('user_id', None)
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                return jsonify({'success': False, 'error': f'Database error during deletion: {str(e)}'}), 500
        return redirect(url_for('settings'))
    notifications = Notification.query.filter_by(user_id=session['user_id'], is_read=False).count()
    return render_template('settings.html', user=user, unread_notifications=notifications)

@app.route('/toggle_theme')
def toggle_theme():
    session['theme'] = 'dark' if session.get('theme') != 'dark' else 'light'
    return redirect(request.referrer or url_for('settings'))

@app.route('/search_page')
def search_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    categories = Category.query.all()
    notifications = Notification.query.filter_by(user_id=session['user_id'], is_read=False).count()
    return render_template('search_notes.html', categories=categories, unread_notifications=notifications)

@app.route('/search', methods=['GET'])
def search_notes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    query = clean(request.args.get('query', '')).lower().strip()
    category = clean(request.args.get('category', '')).strip()
    tag = clean(request.args.get('tag', '')).lower().strip()

    if not query and not category and not tag:
        return redirect(url_for('search_page'))

    notes = Note.query.filter_by(user_id=session['user_id']).all()
    categories = Category.query.all()

    filtered_notes = []
    for note in notes:
        if note.is_unreadable:
            note.content = "This note cannot be decrypted due to a missing or changed encryption key."
        else:
            decrypted_content = decrypt_content(note.content)
            if decrypted_content is None:
                note.is_unreadable = True
                note.content = "This note cannot be decrypted due to a missing or changed encryption key."
                db.session.commit()
            else:
                note.content = decrypted_content

        matches = True

        if query:
            title_lower = note.title.lower() if note.title else ''
            content_lower = note.content.lower() if note.content and not note.is_unreadable else ''
            matches = matches and any([query in title_lower, query in content_lower])

        if category:
            note_category = note.category.strip() if note.category else ''
            matches = matches and (note_category == category)

        if tag:
            note_tags = note.tags.lower().strip() if note.tags else ''
            matches = matches and (tag in note_tags)

        if matches:
            filtered_notes.append(note)

    notifications = Notification.query.filter_by(user_id=session['user_id'], is_read=False).count()
    return render_template('search_notes.html', notes=filtered_notes, categories=categories, unread_notifications=notifications)

@app.route('/category/create', methods=['POST'])
def create_category():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    name = clean(request.form['name'])
    if Category.query.filter_by(name=name).first():
        flash('Category already exists.', 'error')
        return redirect(url_for('index'))
    category = Category(name=name)
    db.session.add(category)
    db.session.commit()
    flash('Category created successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/search_users', methods=['GET'])
def search_users():
    query = clean(request.args.get('query', ''))
    if not query:
        return jsonify([])
    users = User.query.filter(User.username.ilike(f'%{query}%')).all()
    return jsonify([user.username for user in users])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        init_categories()
        db.session.commit()
    app.run(debug=True)