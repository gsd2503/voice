import os
import uuid
from datetime import datetime, timedelta
import json
import csv
import io
import re
import shutil
from functools import wraps
from markupsafe import Markup

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, make_response, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Optional imports
try:
    import pandas as pd
    import folium

    HAS_FOLIUM = True
except ImportError:
    pd = None
    folium = None
    HAS_FOLIUM = False
    print("Folium not installed, map feature will use Leaflet.js")

# Flask App Configuration
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

# ============ CONFIGURATION ============
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data', 'issues.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'mp4', 'avi', 'mov', 'mkv'}

# Service Types Configuration
app.config['SERVICE_TYPES'] = {
    'road': {
        'name': 'Road & Transportation',
        'color': 'blue',
        'icon_class': 'fas fa-road',
        'badge_class': 'bg-primary'
    },
    'pipeline': {
        'name': 'Water Pipeline',
        'color': 'green',
        'icon_class': 'fas fa-faucet',
        'badge_class': 'bg-success'
    },
    'electricity': {
        'name': 'Electricity',
        'color': 'orange',
        'icon_class': 'fas fa-bolt',
        'badge_class': 'bg-warning'
    },
    'garbage': {
        'name': 'Garbage Collection',
        'color': 'purple',
        'icon_class': 'fas fa-trash',
        'badge_class': 'bg-purple'
    },
    'nuisance': {
        'name': 'Public Nuisance',
        'color': 'red',
        'icon_class': 'fas fa-exclamation-triangle',
        'badge_class': 'bg-danger'
    },
    'sewage': {
        'name': 'Sewage & Drainage',
        'color': 'brown',
        'icon_class': 'fas fa-water',
        'badge_class': 'bg-brown'
    },
    'other': {
        'name': 'Other Issues',
        'color': 'gray',
        'icon_class': 'fas fa-question-circle',
        'badge_class': 'bg-secondary'
    }
}

# Priority Levels Configuration
app.config['PRIORITY_LEVELS'] = {
    'low': {
        'name': 'Low',
        'color': 'green',
        'badge_class': 'bg-success'
    },
    'medium': {
        'name': 'Medium',
        'color': 'yellow',
        'badge_class': 'bg-warning'
    },
    'high': {
        'name': 'High',
        'color': 'orange',
        'badge_class': 'bg-danger'
    },
    'critical': {
        'name': 'Critical',
        'color': 'red',
        'badge_class': 'bg-danger'
    }
}

# Issue Statuses Configuration
app.config['ISSUE_STATUSES'] = {
    'pending': {
        'name': 'Pending',
        'color': 'gray',
        'badge_class': 'bg-secondary'
    },
    'in_progress': {
        'name': 'In Progress',
        'color': 'blue',
        'badge_class': 'bg-primary'
    },
    'on_hold': {
        'name': 'On Hold',
        'color': 'orange',
        'badge_class': 'bg-warning'
    },
    'done': {
        'name': 'Resolved',
        'color': 'green',
        'badge_class': 'bg-success'
    },
    'cancelled': {
        'name': 'Cancelled',
        'color': 'red',
        'badge_class': 'bg-danger'
    }
}

# User Roles Configuration
app.config['USER_ROLES'] = {
    'user': 'Citizen User',
    'moderator': 'Moderator',
    'admin': 'Administrator'
}

app.config['APP_NAME'] = 'CivicCare Platform'
# ============ END CONFIGURATION ============

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Create directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('data', exist_ok=True)
os.makedirs('backups', exist_ok=True)


# Simple CSRF token generation
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = str(uuid.uuid4())
    return session['_csrf_token']


app.jinja_env.globals['csrf_token'] = generate_csrf_token


# Custom decorator for admin access
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)

    return decorated_function


# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    role = db.Column(db.String(20), default='user', index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    # Relationships
    issues = db.relationship('Issue', backref='reporter', lazy=True, cascade='all, delete-orphan')
    feedbacks = db.relationship('Feedback', backref='user', lazy=True, cascade='all, delete-orphan')
    solutions = db.relationship('Solution', backref='user', lazy=True, cascade='all, delete-orphan')
    solution_votes = db.relationship('SolutionVote', backref='user', lazy=True, cascade='all, delete-orphan')


class Issue(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    service_type = db.Column(db.String(50), nullable=False, index=True)
    location = db.Column(db.String(200), nullable=False)
    area = db.Column(db.String(100), index=True)
    city = db.Column(db.String(100))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    priority = db.Column(db.String(20), default='medium', index=True)
    status = db.Column(db.String(20), default='pending', index=True)
    date = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    media_paths = db.Column(db.Text)  # JSON string of file paths
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False, index=True)
    upvotes = db.Column(db.Integer, default=0)
    comments = db.Column(db.Integer, default=0)
    assigned_to = db.Column(db.String(100))
    assigned_date = db.Column(db.DateTime)
    resolved_date = db.Column(db.DateTime)
    admin_notes = db.Column(db.Text)

    # Relationships
    feedbacks = db.relationship('Feedback', backref='issue', lazy=True, cascade='all, delete-orphan')
    solutions = db.relationship('Solution', backref='issue', lazy=True, cascade='all, delete-orphan')


class Area(db.Model):
    name = db.Column(db.String(100), primary_key=True)
    issue_count = db.Column(db.Integer, default=0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)


class Feedback(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    issue_id = db.Column(db.String(36), db.ForeignKey('issue.id'), nullable=False, index=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False, index=True)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 stars
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Solution(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    issue_id = db.Column(db.String(36), db.ForeignKey('issue.id'), nullable=False, index=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)
    upvotes = db.Column(db.Integer, default=0)
    downvotes = db.Column(db.Integer, default=0)
    is_accepted = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class SolutionVote(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    solution_id = db.Column(db.String(36), db.ForeignKey('solution.id'), nullable=False, index=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False, index=True)
    vote_type = db.Column(db.String(10), nullable=False)  # 'upvote' or 'downvote'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Unique constraint to prevent multiple votes
    __table_args__ = (db.UniqueConstraint('solution_id', 'user_id', name='unique_solution_vote'),)


@login_manager.user_loader
def load_user(user_id):
    # Using Session.get() for SQLAlchemy 2.0 compatibility
    return db.session.get(User, user_id)


# Helper Functions
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def save_uploaded_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        return unique_filename
    return None


def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_phone(phone):
    if not phone:
        return True
    pattern = r'^[0-9]{10}$'
    return re.match(pattern, phone) is not None


def get_issues_with_filters(service_type=None, status=None, priority=None,
                            location=None, user_id=None, date_from=None, date_to=None):
    query = Issue.query

    if service_type and service_type != 'all':
        query = query.filter_by(service_type=service_type)

    if status and status != 'all':
        query = query.filter_by(status=status)

    if priority and priority != 'all':
        query = query.filter_by(priority=priority)

    if location:
        query = query.filter(Issue.location.contains(location) |
                             Issue.area.contains(location) |
                             Issue.city.contains(location))

    if user_id:
        query = query.filter_by(user_id=user_id)

    if date_from:
        query = query.filter(Issue.date >= date_from)

    if date_to:
        query = query.filter(Issue.date <= date_to)

    return query.order_by(Issue.date.desc()).all()


def get_platform_statistics():
    total_issues = Issue.query.count()

    # Issues by status
    status_counts = {}
    for status in app.config['ISSUE_STATUSES'].keys():
        count = Issue.query.filter_by(status=status).count()
        status_counts[status] = count

    # Issues by service type
    service_counts = {}
    for service in app.config['SERVICE_TYPES'].keys():
        count = Issue.query.filter_by(service_type=service).count()
        service_counts[service] = count

    # Recent issues (last 7 days)
    week_ago = datetime.utcnow() - timedelta(days=7)
    recent_issues = Issue.query.filter(Issue.date >= week_ago).count()

    # Total users
    total_users = User.query.filter_by(role='user').count()

    # Total solutions
    total_solutions = Solution.query.count()

    # Pending issues
    pending_issues = Issue.query.filter_by(status='pending').count()

    # Issues resolved this week
    resolved_this_week = Issue.query.filter(
        Issue.status == 'done',
        Issue.resolved_date >= week_ago
    ).count()

    return {
        'total_issues': total_issues,
        'status_counts': status_counts,
        'service_counts': service_counts,
        'recent_issues': recent_issues,
        'total_users': total_users,
        'total_solutions': total_solutions,
        'pending_issues': pending_issues,
        'resolved_this_week': resolved_this_week
    }


def send_resolution_notification(issue):
    """Send notification when issue is resolved"""
    print(f"Issue resolved: {issue.title}")
    print(f"Notifying user: {issue.reporter.email}")
    print(f"User can now provide feedback at: /issue/{issue.id}/feedback")


def backup_database():
    """Create a backup of the SQLite database"""
    try:
        if os.path.exists('data/issues.db'):
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = f'backups/issues_backup_{timestamp}.db'

            shutil.copy2('data/issues.db', backup_file)

            # Keep only last 7 backups
            backups = sorted([f for f in os.listdir('backups') if f.endswith('.db')])
            if len(backups) > 7:
                for old_backup in backups[:-7]:
                    os.remove(os.path.join('backups', old_backup))

            return True
    except Exception as e:
        print(f"Backup failed: {e}")
    return False


def init_database():
    """Initialize SQLite database with default data"""
    # Check if database already exists
    db_exists = os.path.exists('data/issues.db')

    # Create all tables
    db.create_all()

    if not db_exists:
        print("Creating new SQLite database: data/issues.db")

        # Create default admin if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@civiccare.gov.in',
                password=generate_password_hash('admin123'),
                full_name='System Administrator',
                role='admin'
            )
            db.session.add(admin)
            print("Created admin user")

        # Create test users
        test_users = [
            {
                'username': 'testuser',
                'email': 'user@example.com',
                'password': 'user123',
                'full_name': 'Test User',
                'role': 'user'
            },
            {
                'username': 'john_doe',
                'email': 'john@example.com',
                'password': 'john123',
                'full_name': 'John Doe',
                'role': 'user',
                'phone': '9876543210'
            }
        ]

        for user_data in test_users:
            existing_user = User.query.filter_by(username=user_data['username']).first()
            if not existing_user:
                user = User(
                    username=user_data['username'],
                    email=user_data['email'],
                    password=generate_password_hash(user_data['password']),
                    full_name=user_data['full_name'],
                    role=user_data['role'],
                    phone=user_data.get('phone')
                )
                db.session.add(user)
                print(f"Created user: {user_data['username']}")

        db.session.commit()

        # Create some sample issues with solutions for testing
        if Issue.query.count() == 0:
            print("Creating sample issues...")
            users = User.query.filter_by(role='user').all()
            admin_user = User.query.filter_by(role='admin').first()

            if users:
                sample_issues = [
                    {
                        'title': 'Large pothole on Main Street',
                        'description': 'There is a large pothole near the intersection causing traffic issues and vehicle damage',
                        'service_type': 'road',
                        'location': 'Main Street, City Center',
                        'priority': 'high',
                        'status': 'in_progress',
                        'latitude': 19.0760,
                        'longitude': 72.8777
                    },
                    {
                        'title': 'Garbage not collected for 3 days',
                        'description': 'Garbage bins overflowing in residential area, causing smell and hygiene issues',
                        'service_type': 'garbage',
                        'location': 'Green Park Colony',
                        'priority': 'medium',
                        'status': 'pending',
                        'latitude': 19.0860,
                        'longitude': 72.8877
                    },
                    {
                        'title': 'Street light not working',
                        'description': 'Street light pole number 45 has been not working for 2 weeks, creating safety issues',
                        'service_type': 'electricity',
                        'location': 'Suburban Area',
                        'priority': 'high',
                        'status': 'done',
                        'resolved_date': datetime.utcnow() - timedelta(days=1),
                        'latitude': 19.0660,
                        'longitude': 72.8677
                    }
                ]

                for issue_data in sample_issues:
                    issue = Issue(
                        title=issue_data['title'],
                        description=issue_data['description'],
                        service_type=issue_data['service_type'],
                        location=issue_data['location'],
                        priority=issue_data['priority'],
                        status=issue_data['status'],
                        user_id=users[0].id,
                        latitude=issue_data.get('latitude'),
                        longitude=issue_data.get('longitude')
                    )

                    if 'resolved_date' in issue_data:
                        issue.resolved_date = issue_data['resolved_date']

                    db.session.add(issue)
                    db.session.commit()

                    # Add sample solutions for some issues
                    if issue_data['service_type'] == 'road':
                        sample_solutions = [
                            {
                                'description': 'Temporary repair with cold mix asphalt until permanent fix can be scheduled. Need to place warning signs around the area.',
                                'user_id': users[0].id if len(users) > 0 else admin_user.id
                            },
                            {
                                'description': 'Install warning signs and redirect traffic until repair is completed. Should be done during low traffic hours (10 PM - 5 AM).',
                                'user_id': users[1].id if len(users) > 1 else users[0].id
                            }
                        ]

                        for sol_data in sample_solutions:
                            solution = Solution(
                                issue_id=issue.id,
                                description=sol_data['description'],
                                user_id=sol_data['user_id']
                            )
                            db.session.add(solution)

                db.session.commit()
                print(f"Created {len(sample_issues)} sample issues with coordinates")

        # Create initial area entries
        areas = ['City Center', 'Green Park Colony', 'Suburban Area', 'Industrial Zone']
        for area_name in areas:
            area = Area.query.filter_by(name=area_name).first()
            if not area:
                # Count issues in this area
                issue_count = Issue.query.filter(Issue.location.contains(area_name)).count()
                area = Area(name=area_name, issue_count=issue_count)
                db.session.add(area)

        db.session.commit()

        # Create initial feedback for resolved issue
        resolved_issue = Issue.query.filter_by(status='done').first()
        if resolved_issue:
            feedback = Feedback.query.filter_by(issue_id=resolved_issue.id).first()
            if not feedback:
                feedback = Feedback(
                    issue_id=resolved_issue.id,
                    user_id=resolved_issue.user_id,
                    rating=4,
                    comment='Issue was resolved quickly. Good service!'
                )
                db.session.add(feedback)
                db.session.commit()

        print("Database initialization complete")
        print("Default admin login: admin / admin123")
        print("Test user login: testuser / user123")
    else:
        print("SQLite database already exists: data/issues.db")


# Context processors to make variables available in all templates
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}


@app.context_processor
def inject_config():
    return {
        'SERVICE_TYPES': app.config['SERVICE_TYPES'],
        'PRIORITY_LEVELS': app.config['PRIORITY_LEVELS'],
        'ISSUE_STATUSES': app.config['ISSUE_STATUSES'],
        'USER_ROLES': app.config['USER_ROLES'],
        'APP_NAME': app.config.get('APP_NAME', 'CivicCare')
    }


# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Find user by username or email
        user = User.query.filter((User.username == username) | (User.email == username)).first()

        if user and check_password_hash(user.password, password):
            if not user.is_active:
                flash('Your account has been deactivated. Please contact administrator.', 'error')
                return redirect(url_for('login'))

            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validation
        if not all([full_name, username, email, password, confirm_password]):
            flash('All fields are required', 'error')
        elif password != confirm_password:
            flash('Passwords do not match', 'error')
        elif len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
        elif not validate_email(email):
            flash('Invalid email format', 'error')
        elif not validate_phone(phone):
            flash('Invalid phone number (10 digits required)', 'error')
        elif User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
        else:
            # Create user
            user = User(
                username=username,
                email=email,
                password=generate_password_hash(password),
                full_name=full_name,
                phone=phone,
                role='user'
            )
            db.session.add(user)
            db.session.commit()

            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))

    # Get user statistics
    user_stats = {
        'total_issues': Issue.query.filter_by(user_id=current_user.id).count(),
        'pending_issues': Issue.query.filter_by(user_id=current_user.id, status='pending').count(),
        'resolved_issues': Issue.query.filter_by(user_id=current_user.id, status='done').count(),
        'total_solutions': Solution.query.filter_by(user_id=current_user.id).count(),
        'accepted_solutions': Solution.query.filter_by(user_id=current_user.id, is_accepted=True).count()
    }

    # Get recent issues
    recent_issues = Issue.query.filter_by(user_id=current_user.id) \
        .order_by(Issue.date.desc()) \
        .limit(5).all()

    # Get popular solutions
    popular_solutions = Solution.query.filter(Solution.issue.has(user_id=current_user.id)) \
        .order_by((Solution.upvotes - Solution.downvotes).desc()) \
        .limit(3).all()

    return render_template('dashboard.html',
                           user_stats=user_stats,
                           recent_issues=recent_issues,
                           popular_solutions=popular_solutions)


@app.route('/report-issue', methods=['GET', 'POST'])
@login_required
def report_issue():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        service_type = request.form.get('service_type')
        priority = request.form.get('priority')
        location = request.form.get('location')
        area = request.form.get('area')
        city = request.form.get('city')
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')

        # Debug: Print received data
        print(f"Service Type: {service_type}")
        print(f"Title: {title}")
        print(f"Description: {description}")
        print(f"Location: {location}")
        print(f"Priority: {priority}")

        if not all([title, description, service_type, location, priority]):
            flash('All required fields must be filled', 'error')
            return redirect(url_for('report_issue'))

        # Handle file uploads
        media_paths = []
        files = request.files.getlist('media_files')
        for file in files:
            if file.filename:
                filename = save_uploaded_file(file)
                if filename:
                    media_paths.append(filename)

        # Create issue
        issue = Issue(
            title=title,
            description=description,
            service_type=service_type,
            priority=priority,
            location=location,
            area=area,
            city=city,
            latitude=float(latitude) if latitude and latitude.strip() else None,
            longitude=float(longitude) if longitude and longitude.strip() else None,
            media_paths=json.dumps(media_paths),
            user_id=current_user.id
        )

        db.session.add(issue)
        db.session.commit()

        flash('Issue reported successfully!', 'success')
        return redirect(url_for('my_issues'))

    return render_template('report_issue.html')


@app.route('/my-issues')
@login_required
def my_issues():
    service_filter = request.args.get('service_type', 'all')
    status_filter = request.args.get('status', 'all')

    issues = get_issues_with_filters(
        service_type=service_filter if service_filter != 'all' else None,
        status=status_filter if status_filter != 'all' else None,
        user_id=current_user.id
    )

    # Check which issues have feedback
    issues_with_feedback = []
    for issue in issues:
        has_feedback = Feedback.query.filter_by(
            issue_id=issue.id,
            user_id=current_user.id
        ).first() is not None

        solutions_count = Solution.query.filter_by(issue_id=issue.id).count()

        issues_with_feedback.append({
            'issue': issue,
            'has_feedback': has_feedback,
            'solutions_count': solutions_count
        })

    return render_template('my_issues.html',
                           issues_with_feedback=issues_with_feedback)


@app.route('/view-issues')
@login_required
def view_issues():
    service_filter = request.args.get('service_type', 'all')
    status_filter = request.args.get('status', 'all')
    priority_filter = request.args.get('priority', 'all')
    location_filter = request.args.get('location', '')

    issues = get_issues_with_filters(
        service_type=service_filter if service_filter != 'all' else None,
        status=status_filter if status_filter != 'all' else None,
        priority=priority_filter if priority_filter != 'all' else None,
        location=location_filter if location_filter else None
    )

    # Get solutions count for each issue
    issues_with_counts = []
    for issue in issues:
        solutions_count = Solution.query.filter_by(issue_id=issue.id).count()
        issues_with_counts.append({
            'issue': issue,
            'solutions_count': solutions_count
        })

    return render_template('view_issues.html', issues_with_counts=issues_with_counts)


@app.route('/map')
@login_required
def map_view():
    # Get all issues (not just those with coordinates)
    all_issues = Issue.query.all()

    # Get filter parameters
    service_filter = request.args.get('service_type', 'all')
    status_filter = request.args.get('status', 'all')

    # Apply filters
    filtered_issues = []
    for issue in all_issues:
        if service_filter != 'all' and issue.service_type != service_filter:
            continue
        if status_filter != 'all' and issue.status != status_filter:
            continue
        filtered_issues.append(issue)

    # Try to create map if folium is available
    map_html = None
    if HAS_FOLIUM:
        # Get issues with coordinates
        geo_issues = [issue for issue in filtered_issues
                      if issue.latitude is not None and issue.longitude is not None]

        if geo_issues:
            # Create map centered on first issue or default location
            if geo_issues:
                center = [geo_issues[0].latitude, geo_issues[0].longitude]
            else:
                center = [20.5937, 78.9629]  # Default to India

            m = folium.Map(location=center, zoom_start=12)

            colors = {
                'road': 'blue',
                'pipeline': 'green',
                'electricity': 'orange',
                'garbage': 'purple',
                'nuisance': 'red',
                'sewage': 'brown',
                'other': 'gray'
            }

            for issue in geo_issues:
                color = colors.get(issue.service_type, 'gray')
                service_info = app.config['SERVICE_TYPES'].get(issue.service_type)
                service_name = service_info['name'] if service_info else issue.service_type
                status_info = app.config['ISSUE_STATUSES'].get(issue.status)
                status_name = status_info['name'] if status_info else issue.status

                popup_html = f"""
                <div style="width: 200px;">
                    <h5>{issue.title}</h5>
                    <p><strong>Type:</strong> {service_name}</p>
                    <p><strong>Status:</strong> {status_name}</p>
                    <p><strong>Priority:</strong> {issue.priority.title()}</p>
                    <p>{issue.description[:100]}...</p>
                    <a href="/issue/{issue.id}/solutions" style="color: #667eea; text-decoration: none;">
                        <i class="fas fa-lightbulb"></i> View Solutions
                    </a>
                </div>
                """

                folium.Marker(
                    [issue.latitude, issue.longitude],
                    popup=folium.Popup(popup_html, max_width=250),
                    tooltip=issue.title,
                    icon=folium.Icon(color=color, icon='info-sign')
                ).add_to(m)

            map_html = m._repr_html_()

    return render_template('map.html',
                           map_html=map_html,
                           issues=filtered_issues,
                           all_issues=all_issues,
                           HAS_FOLIUM=HAS_FOLIUM)


@app.route('/profile')
@login_required
def profile():
    user_stats = {
        'total_issues': Issue.query.filter_by(user_id=current_user.id).count(),
        'pending_issues': Issue.query.filter_by(user_id=current_user.id, status='pending').count(),
        'resolved_issues': Issue.query.filter_by(user_id=current_user.id, status='done').count(),
        'total_solutions': Solution.query.filter_by(user_id=current_user.id).count(),
        'accepted_solutions': Solution.query.filter_by(user_id=current_user.id, is_accepted=True).count(),
        'solution_upvotes': db.session.query(db.func.sum(Solution.upvotes)).filter_by(
            user_id=current_user.id).scalar() or 0
    }

    # Get recent solutions
    recent_solutions = Solution.query.filter_by(user_id=current_user.id) \
        .order_by(Solution.created_at.desc()) \
        .limit(5).all()

    return render_template('profile.html',
                           user_stats=user_stats,
                           recent_solutions=recent_solutions)


# Feedback Routes
@app.route('/issue/<issue_id>/feedback', methods=['GET', 'POST'])
@login_required
def issue_feedback(issue_id):
    issue = Issue.query.get_or_404(issue_id)

    # Check if user is the reporter of this issue
    if issue.user_id != current_user.id:
        flash('You can only provide feedback on your own issues', 'error')
        return redirect(url_for('my_issues'))

    # Check if issue is resolved
    if issue.status != 'done':
        flash('You can only provide feedback on resolved issues', 'error')
        return redirect(url_for('my_issues'))

    # Check if feedback already exists
    existing_feedback = Feedback.query.filter_by(
        issue_id=issue_id,
        user_id=current_user.id
    ).first()

    if request.method == 'POST':
        rating = request.form.get('rating', type=int)
        comment = request.form.get('comment', '')

        if not rating or rating < 1 or rating > 5:
            flash('Please provide a valid rating (1-5 stars)', 'error')
            return redirect(url_for('issue_feedback', issue_id=issue_id))

        if existing_feedback:
            # Update existing feedback
            existing_feedback.rating = rating
            existing_feedback.comment = comment
            flash('Feedback updated successfully!', 'success')
        else:
            # Create new feedback
            feedback = Feedback(
                issue_id=issue_id,
                user_id=current_user.id,
                rating=rating,
                comment=comment
            )
            db.session.add(feedback)
            flash('Thank you for your feedback!', 'success')

        db.session.commit()
        return redirect(url_for('my_issues'))

    return render_template('feedback.html',
                           issue=issue,
                           existing_feedback=existing_feedback)


# Solution Routes
@app.route('/issue/<issue_id>/solutions')
@login_required
def view_solutions(issue_id):
    issue = Issue.query.get_or_404(issue_id)

    # Check if user has already voted on solutions
    user_votes = {}
    if current_user.is_authenticated:
        votes = SolutionVote.query.filter_by(user_id=current_user.id).all()
        user_votes = {vote.solution_id: vote.vote_type for vote in votes}

    solutions = Solution.query.filter_by(issue_id=issue_id) \
        .order_by(Solution.is_accepted.desc(),
                  (Solution.upvotes - Solution.downvotes).desc()) \
        .all()

    # Check if user has already submitted a solution
    user_solution = Solution.query.filter_by(
        issue_id=issue_id,
        user_id=current_user.id
    ).first()

    return render_template('solutions.html',
                           issue=issue,
                           solutions=solutions,
                           user_votes=user_votes,
                           user_solution=user_solution)


@app.route('/issue/<issue_id>/add-solution', methods=['GET', 'POST'])
@login_required
def add_solution(issue_id):
    issue = Issue.query.get_or_404(issue_id)

    # Check if issue is resolved
    if issue.status == 'done':
        flash('Cannot add solutions to resolved issues', 'error')
        return redirect(url_for('view_solutions', issue_id=issue_id))

    # Check if user already submitted a solution
    existing_solution = Solution.query.filter_by(
        issue_id=issue_id,
        user_id=current_user.id
    ).first()

    if existing_solution:
        flash('You have already submitted a solution for this issue', 'warning')
        return redirect(url_for('view_solutions', issue_id=issue_id))

    if request.method == 'POST':
        description = request.form.get('description')

        if not description or len(description.strip()) < 10:
            flash('Please provide a detailed solution description (minimum 10 characters)', 'error')
            return redirect(url_for('add_solution', issue_id=issue_id))

        solution = Solution(
            issue_id=issue_id,
            user_id=current_user.id,
            description=description.strip()
        )

        db.session.add(solution)
        db.session.commit()

        flash('Your solution has been submitted!', 'success')
        return redirect(url_for('view_solutions', issue_id=issue_id))

    return render_template('add_solution.html', issue=issue)


@app.route('/solution/<solution_id>/vote', methods=['POST'])
@login_required
def vote_solution(solution_id):
    solution = Solution.query.get_or_404(solution_id)
    vote_type = request.form.get('vote_type')

    if vote_type not in ['upvote', 'downvote']:
        return jsonify({'error': 'Invalid vote type'}), 400

    # Check if user already voted
    existing_vote = SolutionVote.query.filter_by(
        solution_id=solution_id,
        user_id=current_user.id
    ).first()

    if existing_vote:
        # Update existing vote
        if existing_vote.vote_type != vote_type:
            # Remove old vote count
            if existing_vote.vote_type == 'upvote':
                solution.upvotes -= 1
            else:
                solution.downvotes -= 1

            # Add new vote count
            if vote_type == 'upvote':
                solution.upvotes += 1
            else:
                solution.downvotes += 1

            existing_vote.vote_type = vote_type
            db.session.commit()

            return jsonify({
                'success': True,
                'upvotes': solution.upvotes,
                'downvotes': solution.downvotes,
                'action': 'updated'
            })
        else:
            # Remove vote (toggle)
            if vote_type == 'upvote':
                solution.upvotes -= 1
            else:
                solution.downvotes -= 1

            db.session.delete(existing_vote)
            db.session.commit()

            return jsonify({
                'success': True,
                'upvotes': solution.upvotes,
                'downvotes': solution.downvotes,
                'action': 'removed'
            })
    else:
        # Add new vote
        vote = SolutionVote(
            solution_id=solution_id,
            user_id=current_user.id,
            vote_type=vote_type
        )

        if vote_type == 'upvote':
            solution.upvotes += 1
        else:
            solution.downvotes += 1

        db.session.add(vote)
        db.session.commit()

        return jsonify({
            'success': True,
            'upvotes': solution.upvotes,
            'downvotes': solution.downvotes,
            'action': 'added'
        })


@app.route('/admin/solution/<solution_id>/accept', methods=['POST'])
@login_required
@admin_required
def accept_solution(solution_id):
    solution = Solution.query.get_or_404(solution_id)

    # Unaccept any previously accepted solution for this issue
    Solution.query.filter_by(issue_id=solution.issue_id, is_accepted=True) \
        .update({'is_accepted': False})

    # Accept this solution
    solution.is_accepted = True
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Solution marked as accepted'
    })


@app.route('/solution/<solution_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_solution(solution_id):
    solution = Solution.query.get_or_404(solution_id)

    # Check if user owns the solution
    if solution.user_id != current_user.id and current_user.role != 'admin':
        flash('You can only edit your own solutions', 'error')
        return redirect(url_for('view_solutions', issue_id=solution.issue_id))

    if request.method == 'POST':
        description = request.form.get('description')

        if not description or len(description.strip()) < 10:
            flash('Please provide a detailed solution description (minimum 10 characters)', 'error')
            return redirect(url_for('edit_solution', solution_id=solution_id))

        solution.description = description.strip()
        db.session.commit()

        flash('Solution updated successfully!', 'success')
        return redirect(url_for('view_solutions', issue_id=solution.issue_id))

    return render_template('edit_solution.html', solution=solution)


@app.route('/solution/<solution_id>/delete', methods=['POST'])
@login_required
def delete_solution(solution_id):
    solution = Solution.query.get_or_404(solution_id)
    issue_id = solution.issue_id

    # Check if user owns the solution or is admin
    if solution.user_id != current_user.id and current_user.role != 'admin':
        flash('You can only delete your own solutions', 'error')
        return redirect(url_for('view_solutions', issue_id=issue_id))

    # Delete associated votes first
    SolutionVote.query.filter_by(solution_id=solution_id).delete()

    # Delete the solution
    db.session.delete(solution)
    db.session.commit()

    flash('Solution deleted successfully', 'success')
    return redirect(url_for('view_solutions', issue_id=issue_id))


# Admin Routes
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    stats = get_platform_statistics()

    # Get recent issues
    recent_issues = Issue.query.order_by(Issue.date.desc()).limit(5).all()

    # Get recent feedback
    recent_feedback = Feedback.query.order_by(Feedback.created_at.desc()).limit(3).all()

    # Get recent users
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()

    return render_template('admin_dashboard.html',
                           stats=stats,
                           recent_issues=recent_issues,
                           recent_feedback=recent_feedback,
                           recent_users=recent_users)


@app.route('/admin/issues')
@login_required
@admin_required
def admin_issues():
    service_filter = request.args.get('service_type', 'all')
    status_filter = request.args.get('status', 'all')
    priority_filter = request.args.get('priority', 'all')
    date_filter = request.args.get('date_filter', 'all')

    # Apply date filter
    date_from = None
    if date_filter == 'today':
        date_from = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    elif date_filter == '7d':
        date_from = datetime.utcnow() - timedelta(days=7)
    elif date_filter == '30d':
        date_from = datetime.utcnow() - timedelta(days=30)

    issues = get_issues_with_filters(
        service_type=service_filter if service_filter != 'all' else None,
        status=status_filter if status_filter != 'all' else None,
        priority=priority_filter if priority_filter != 'all' else None,
        date_from=date_from
    )

    return render_template('admin_issues.html', issues=issues)


@app.route('/admin/analytics')
@login_required
@admin_required
def admin_analytics():
    stats = get_platform_statistics()
    issues = Issue.query.all()

    # Create charts data
    service_data = []
    for service_type, count in stats['service_counts'].items():
        service_info = app.config['SERVICE_TYPES'].get(service_type, {'name': service_type})
        service_data.append({
            'service': service_info['name'],
            'service_key': service_type,
            'count': count
        })

    status_data = []
    for status_key, count in stats['status_counts'].items():
        status_info = app.config['ISSUE_STATUSES'].get(status_key, {'name': status_key})
        status_data.append({
            'status': status_info['name'],
            'status_key': status_key,
            'count': count
        })

    # Area distribution
    area_data = {}
    for issue in issues:
        if issue.area:
            area_data[issue.area] = area_data.get(issue.area, 0) + 1

    top_areas = sorted(area_data.items(), key=lambda x: x[1], reverse=True)[:10]

    # Calculate date 30 days ago for new users calculation
    date_30_days_ago = datetime.utcnow() - timedelta(days=30)

    # Get monthly statistics
    monthly_stats = []
    for i in range(6):
        month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        month_start = month_start - timedelta(days=30 * i)
        month_end = month_start + timedelta(days=30)

        month_issues = Issue.query.filter(
            Issue.date >= month_start,
            Issue.date < month_end
        ).count()

        month_resolved = Issue.query.filter(
            Issue.status == 'done',
            Issue.resolved_date >= month_start,
            Issue.resolved_date < month_end
        ).count()

        monthly_stats.append({
            'month': month_start.strftime('%b %Y'),
            'issues': month_issues,
            'resolved': month_resolved
        })

    monthly_stats.reverse()

    return render_template('admin_analytics.html',
                           stats=stats,
                           service_data=service_data,
                           status_data=status_data,
                           top_areas=top_areas,
                           monthly_stats=monthly_stats,
                           date_30_days_ago=date_30_days_ago)


@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()

    # Calculate date 30 days ago for new users calculation
    date_30_days_ago = datetime.utcnow() - timedelta(days=30)

    # Calculate statistics for each user
    users_with_stats = []
    for user in users:
        issues_count = Issue.query.filter_by(user_id=user.id).count()
        solutions_count = Solution.query.filter_by(user_id=user.id).count()
        feedback_count = Feedback.query.filter_by(user_id=user.id).count()

        users_with_stats.append({
            'user': user,
            'issues_count': issues_count,
            'solutions_count': solutions_count,
            'feedback_count': feedback_count
        })

    return render_template('admin_users.html',
                           users_with_stats=users_with_stats,
                           date_30_days_ago=date_30_days_ago)


@app.route('/admin/feedback')
@login_required
@admin_required
def admin_feedback():
    feedbacks = Feedback.query.order_by(Feedback.created_at.desc()).all()

    # Calculate average rating
    avg_rating = 0
    if feedbacks:
        total_rating = sum(f.rating for f in feedbacks)
        avg_rating = round(total_rating / len(feedbacks), 1)

    # Get feedback statistics
    rating_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
    for feedback in feedbacks:
        rating_counts[feedback.rating] = rating_counts.get(feedback.rating, 0) + 1

    # Get count of resolved issues
    issues_done_count = Issue.query.filter_by(status='done').count()

    return render_template('admin_feedback.html',
                           feedbacks=feedbacks,
                           avg_rating=avg_rating,
                           rating_counts=rating_counts,
                           issues_done_count=issues_done_count)


@app.route('/admin/update-issue-status/<issue_id>', methods=['POST'])
@login_required
@admin_required
def update_issue_status(issue_id):
    issue = Issue.query.get_or_404(issue_id)
    new_status = request.form.get('status')

    if new_status in app.config['ISSUE_STATUSES']:
        issue.status = new_status

        if new_status == 'done':
            issue.resolved_date = datetime.utcnow()
            # Send notification when issue is resolved
            send_resolution_notification(issue)
        elif new_status == 'in_progress':
            issue.assigned_date = datetime.utcnow()
        elif new_status == 'cancelled':
            issue.resolved_date = datetime.utcnow()

        db.session.commit()

        return jsonify({'success': True})

    return jsonify({'error': 'Invalid status'}), 400


@app.route('/admin/bulk-update-status', methods=['POST'])
@login_required
@admin_required
def bulk_update_status():
    """Bulk update status for multiple issues"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        issue_ids = data.get('issue_ids', [])
        new_status = data.get('status')

        if not issue_ids:
            return jsonify({'error': 'No issues selected'}), 400

        if not new_status or new_status not in app.config['ISSUE_STATUSES']:
            return jsonify({'error': 'Invalid status'}), 400

        # Update each issue
        updated_count = 0
        for issue_id in issue_ids:
            issue = Issue.query.get(issue_id)
            if issue:
                issue.status = new_status
                if new_status == 'done':
                    issue.resolved_date = datetime.utcnow()
                elif new_status == 'in_progress':
                    issue.assigned_date = datetime.utcnow()
                updated_count += 1

        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Updated {updated_count} issue(s)',
            'updated_count': updated_count
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/admin/export-issues')
@login_required
@admin_required
def admin_export_issues():
    """Export selected issues as CSV"""
    issue_ids = request.args.get('ids', '').split(',')
    if not issue_ids or issue_ids[0] == '':
        flash('No issues selected for export', 'error')
        return redirect(url_for('admin_issues'))

    issues = Issue.query.filter(Issue.id.in_(issue_ids)).all()

    # Create CSV response
    output = io.StringIO()
    writer = csv.writer(output)

    # Write headers
    writer.writerow(['ID', 'Title', 'Description', 'Service Type', 'Location',
                     'Priority', 'Status', 'Reporter', 'Email', 'Date Reported',
                     'Resolved Date', 'Solutions Count'])

    # Write data
    for issue in issues:
        service_info = app.config['SERVICE_TYPES'].get(issue.service_type, {})
        service_name = service_info.get('name', issue.service_type)

        writer.writerow([
            issue.id,
            issue.title,
            issue.description[:100] + '...' if len(issue.description) > 100 else issue.description,
            service_name,
            issue.location,
            issue.priority,
            issue.status,
            issue.reporter.full_name if issue.reporter else 'Unknown',
            issue.reporter.email if issue.reporter else '',
            issue.date.strftime('%Y-%m-%d %H:%M:%S'),
            issue.resolved_date.strftime('%Y-%m-%d %H:%M:%S') if issue.resolved_date else 'Not resolved',
            len(issue.solutions)
        ])

    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=civiccare_issues_export.csv'
    response.headers['Content-type'] = 'text/csv'
    return response


@app.route('/admin/user/<user_id>/toggle-active', methods=['POST'])
@login_required
@admin_required
def toggle_user_active(user_id):
    """Toggle user active status"""
    if user_id == current_user.id:
        return jsonify({'error': 'Cannot deactivate yourself'}), 400

    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()

    return jsonify({
        'success': True,
        'is_active': user.is_active,
        'message': f'User {"activated" if user.is_active else "deactivated"} successfully'
    })


@app.route('/admin/issue/<issue_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_issue_admin(issue_id):
    """Delete an issue (admin only)"""
    issue = Issue.query.get_or_404(issue_id)

    # Delete associated records
    Feedback.query.filter_by(issue_id=issue_id).delete()

    # Delete solutions and their votes
    solutions = Solution.query.filter_by(issue_id=issue_id).all()
    for solution in solutions:
        SolutionVote.query.filter_by(solution_id=solution.id).delete()
    Solution.query.filter_by(issue_id=issue_id).delete()

    # Delete the issue
    db.session.delete(issue)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Issue deleted successfully'
    })


@app.route('/admin/backup-database', methods=['POST'])
@login_required
@admin_required
def backup_database_route():
    """Create a database backup"""
    try:
        if backup_database():
            return jsonify({'success': True, 'message': 'Database backup created successfully'})
        else:
            return jsonify({'error': 'Backup failed'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/issue/<issue_id>/update-coordinates', methods=['POST'])
@login_required
def update_issue_coordinates(issue_id):
    """Update issue coordinates"""
    issue = Issue.query.get_or_404(issue_id)

    # Check if user owns the issue or is admin
    if issue.user_id != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Permission denied'}), 403

    try:
        data = request.get_json()
        latitude = data.get('latitude')
        longitude = data.get('longitude')

        if latitude is None or longitude is None:
            return jsonify({'error': 'Latitude and longitude required'}), 400

        issue.latitude = float(latitude)
        issue.longitude = float(longitude)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Coordinates updated successfully'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))


# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    error_id = str(uuid.uuid4())[:8]
    app.logger.error(f"Error {error_id}: {str(error)}")
    return render_template('500.html', error_id=error_id), 500


# Health check endpoint
@app.route('/health')
def health_check():
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e)
        }), 500


if __name__ == '__main__':
    # Create directories if they don't exist
    directories = ['data', 'uploads', 'templates', 'static', 'backups']
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")

    with app.app_context():
        init_database()

    print("\n" + "=" * 50)
    print("CivicCare Platform Started Successfully!")
    print("=" * 50)
    print("\nAccess URLs:")
    print(f"• Main Application: http://localhost:5000")
    print(f"• Health Check: http://localhost:5000/health")
    print("\nDefault Login Credentials:")
    print("• Admin: admin / admin123")
    print("• User: testuser / user123")
    print("\nDatabase: SQLite (data/issues.db)")
    print("=" * 50 + "\n")

    # For development
    app.run(debug=True, host='0.0.0.0', port=5000)