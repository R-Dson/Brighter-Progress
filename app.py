from flask import Flask, render_template, request, session, redirect, url_for, send_from_directory, jsonify
import bleach
from datetime import timedelta
from flask_limiter import Limiter
from flask_limiter.errors import RateLimitExceeded
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask_limiter.util import get_remote_address
import os
import base64
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
from dotenv import load_dotenv
import re
from cryptography.fernet import Fernet

# Set to True for development/debug, False for production
DEBUG_MODE = False #True

def sanitize_input(input_str, allow_html=False):
    """Sanitize user input by removing special characters and limiting length"""
    if not input_str:
        return input_str
    
    # Define allowed HTML tags and attributes if needed
    ALLOWED_TAGS = ['b', 'i', 'u', 'em', 'strong', 'a']
    ALLOWED_ATTRIBUTES = {'a': ['href', 'title']}
    
    # Remove any non-alphanumeric characters except basic punctuation
    if allow_html:
        # Use bleach for HTML sanitization
        sanitized = bleach.clean(input_str, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES)
    else:
        # For regular input, be more strict
        sanitized = re.sub(r'[^a-zA-Z0-9_\-\.@]', '', input_str)
    
    # Limit length and strip whitespace
    sanitized = sanitized[:100].strip()
    
    # Additional security checks
    if not allow_html and any(char in sanitized for char in ['<', '>', '"', "'", '&']):
        return ''
    
    return sanitized

from mistralai import Mistral
from langchain_core.output_parsers import JsonOutputParser
from werkzeug.security import generate_password_hash, check_password_hash
import base64
from functools import wraps

app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'', 'https://cdn.tailwindcss.com', 'https://cdn.jsdelivr.net/npm/chart.js', '\'unsafe-inline\''],
    'style-src': ['\'self\'', '\'unsafe-inline\''],
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'frame-ancestors': '\'none\'',
    'form-action': '\'self\'',
}

permissions_policy = {
    'geolocation': '()',
    'microphone': '()',
    'camera': '()',
}

security_headers = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
}

Talisman(app,
         content_security_policy=csp,
         force_https=True,
         strict_transport_security=True,
         session_cookie_secure=True,
         permissions_policy=permissions_policy)

csrf = CSRFProtect(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///levels.db'
app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:///users.db',
    'levels': 'sqlite:///levels.db'
}

load_dotenv()

app.config['MISTRAL_API_KEY'] = os.getenv('MISTRAL_API_KEY')
db = SQLAlchemy(app)

#migrate = Migrate(app, db, directory='./migrations', compare_type=True)

app.secret_key = os.getenv('FLASK_SECRET_KEY')
app.app_wide_encryption_key = os.getenv('APP_WIDE_ENCRYPTION_KEY')

# Configure secure session cookies

app.config.update(
    SESSION_COOKIE_SECURE=True,  # Only send cookies over HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Prevent JavaScript access to cookies
    SESSION_COOKIE_SAMESITE='Lax',  # Prevent CSRF
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)  # Session expiration
)

mistral_client = Mistral(api_key=app.config['MISTRAL_API_KEY'])
# Define the path to the image folder
app.config['IMAGE_FOLDER'] = 'images'

class AuthUser(db.Model):
    __bind_key__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    game_username = db.Column(db.String(80), unique=True, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)

    def encrypt_field(self, field):
        cipher_suite = Fernet(app.app_wide_encryption_key.encode())
        return cipher_suite.encrypt(field.encode()).decode()

    def decrypt_game_username_with_key(self):
        if self.game_username:
            return Fernet(app.app_wide_encryption_key.encode()).decrypt(self.game_username.encode()).decode()
        return None

"""class User(db.Model):
    __bind_key__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))"""

class User(db.Model):
    __bind_key__ = 'levels'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    updates = db.relationship('Update', backref='user', lazy=True)


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if session.get('user_id') is None:
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

class Update(db.Model):
    __bind_key__ = 'levels'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    region_skills = db.relationship('RegionSkill', backref='update', lazy=True)

class RegionSkill(db.Model):
    __bind_key__ = 'levels'
    id = db.Column(db.Integer, primary_key=True)
    update_id = db.Column(db.Integer, db.ForeignKey('update.id'), nullable=False)
    region_name = db.Column(db.String, nullable=False)
    skills = db.relationship('Skill', backref='region_skill', lazy=True)

class Skill(db.Model):
    __bind_key__ = 'levels'
    id = db.Column(db.Integer, primary_key=True)
    region_skill_id = db.Column(db.Integer, db.ForeignKey('region_skill.id'), nullable=False)
    name = db.Column(db.String, nullable=False)
    level = db.Column(db.Integer, nullable=False)

# Ensure the database tables are created after all models and config are defined
with app.app_context():
    db.create_all()

@app.context_processor
def inject_now():
    return {'now': datetime.now()}

from collections import defaultdict

from datetime import datetime, timedelta

@app.route('/')
def index():
    # Get the latest updates, limit to a reasonable number
    recent_updates = Update.query.order_by(Update.timestamp.desc()).limit(10).all()
    # Extract unique usernames from the recent updates
    recently_updated_users = list(set(update.user.username for update in recent_updates))

    # The original code for grouping updates by date is commented out, so I'll leave it as is.
    #for update in updates:
    #    updates_by_date[update.timestamp.date()][update.user.username].append(update)
    return render_template('index.html', 
                         recently_updated_users=recently_updated_users, 
                         now=datetime.now(),
                         title="Level Tracker")

@app.route('/search')
def search():
    username = request.args.get('username')
    updates_by_date = defaultdict(lambda: defaultdict(list))
    progress_data = {}
    level_history = {}
    region_totals = {}
    region_level_history = {}
    if username:
        user = User.query.filter_by(username=username).first()
        if user:
            updates = Update.query.filter_by(user_id=user.id).order_by(Update.timestamp.desc()).all()
            for update in updates:
                updates_by_date[update.timestamp.date()][update.user.username].append(update)
            
            # Get the latest update
            latest_update = Update.query.filter_by(user_id=user.id).order_by(Update.timestamp.desc()).first()
            
            # Get the update from one day ago
            from datetime import datetime, timedelta
            one_day_ago = datetime.now() - timedelta(days=1)
            earliest_update = Update.query.filter_by(user_id=user.id).filter(Update.timestamp >= one_day_ago).order_by(Update.timestamp.asc()).first()

            if earliest_update and latest_update:
                progress_data = {}
                
                # Fetch skill levels for the earliest and latest updates
                earliest_skills = Skill.query.join(RegionSkill).filter(RegionSkill.update_id == earliest_update.id).all()
                latest_skills = Skill.query.join(RegionSkill).filter(RegionSkill.update_id == latest_update.id).all()

                # Organize skills by region and name for easier comparison
                earliest_skills_map = {(skill.region_skill.region_name, skill.name): skill.level for skill in earliest_skills}
                latest_skills_map = {(skill.region_skill.region_name, skill.name): skill.level for skill in latest_skills}

                # Calculate progress and region totals
                regions = set(skill[0] for skill in latest_skills_map.keys())
                region_totals = {}
                for region_name in regions:
                    latest_region_total = 0
                    earliest_region_total = 0
                    progress_data[region_name] = {}
                    # Get all unique skill names from both updates
                    skill_names = set(skill[1] for skill in latest_skills_map.keys() if skill[0] == region_name) | \
                                 set(skill[1] for skill in earliest_skills_map.keys() if skill[0] == region_name)
                    
                    for skill_name in skill_names:
                        latest_level = latest_skills_map.get((region_name, skill_name), 0)
                        earliest_level = earliest_skills_map.get((region_name, skill_name), 0)
                        latest_region_total += latest_level
                        earliest_region_total += earliest_level
                        progress_data[region_name][skill_name] = {
                            'previous': earliest_level,
                            'current': latest_level
                        }
                    region_totals[region_name] = {
                        'previous': earliest_region_total,
                        'current': latest_region_total
                    }

            # Fetch level history for the last 30 days
            from datetime import datetime, timedelta
            thirty_days_ago = datetime.now() - timedelta(days=30)
            recent_updates = Update.query.filter_by(user_id=user.id).filter(Update.timestamp >= thirty_days_ago).order_by(Update.timestamp.asc()).all()

            # Create a dictionary to store the latest update for each date
            latest_updates_by_date = {}
            for update in recent_updates:
                date = update.timestamp.strftime('%Y-%m-%d')
                # Only keep the latest update for each date
                if date not in latest_updates_by_date or update.timestamp > latest_updates_by_date[date].timestamp:
                    latest_updates_by_date[date] = update

            level_history = defaultdict(lambda: defaultdict(int))
            region_level_history = defaultdict(lambda: defaultdict(int))

            # Process the latest updates for each date
            for date, update in latest_updates_by_date.items():
                for region_skill in update.region_skills:
                    for skill in region_skill.skills:
                        # Store the skill level for this date
                        level_history[skill.name][date] = skill.level
                    # Calculate and store the total region level for this date
                    region_total_level = sum(skill.level for skill in region_skill.skills)
                    region_level_history[region_skill.region_name][date] = region_total_level

    return render_template(
        'search_results.html',
        updates_by_date=updates_by_date,
        search_term=username,
        progress_data=progress_data,
        level_history=level_history,
        region_totals=region_totals,
        region_level_history=region_level_history
    )

@app.route('/paste_image', methods=['POST'])
@login_required
def paste_image():
    if request.method == 'POST':
        @limiter.limit("2 per 30 minutes")
        def handle_post():
            return request.form['image_data']
        image_data = handle_post()
        # Remove the Data URL prefix if present
        #if image_data.startswith('data:image'):
        #    image_data = image_data.split('data:')[1]
        try:
            prompt = """You need to extract the skills from the image and return them in JSON format.
Each skill should be a dictionary with the keys 'Skill' and 'Level'.
The regions are: Hopeport, Hopeforest, Mine of Mantuban, Crenopolis. Ordered by row.
Make sure the image is from a video game (with images etc) and simply not just text.
Only include the skills present in the image. Do not add any extra information or explanations.
Here are the following region and their respective skills in JSON format.
{
  "Hopeport": [
    "Guard",
    "Chef",
    "Fisher",
    "Forager",
    "Alchemist"
  ],
  "Hopeforest": [
    "Scout",
    "Gatherer",
    "Woodcutter",
    "Carpenter"
  ],
  "Mine of Mantuban": [
    "Minefighter",
    "Bonewright",
    "Miner",
    "Blacksmith",
    "Stonemason"
  ],
  "Crenopolis": [
    "Watchperson",
    "Detective",
    "Leatherworker",
    "Merchant"
  ],
  "Stonemaw Hill": [
    "Shieldbearer",
    "Builder",
    "Armorer",
    "Delver"
  ]
}
Extract the skills and their levels from this image, organized by region.
Return the data as a JSON object where the keys are the region names and the values are lists of skills.
"""
            # Use the image data as-is since it already has the correct prefix from the JavaScript
            list_image = image_data
            chat_response = mistral_client.chat.complete(
                model="pixtral-12b-2409",
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt},
                            {"type": "image_url", "image_url": list_image},
                        ]
                    }
                ],
            )
            extracted_text = chat_response.choices[0].message.content
            #print("Raw Response:", extracted_text)
            parser = JsonOutputParser()
            parsed_data = parser.parse(extracted_text)
            #print("Parsed Data:", parsed_data)
            #print("Parsed Data Type:", type(parsed_data))

            if isinstance(parsed_data, dict):
                username = session.get('game_username')
                user = User.query.filter_by(username=username).first()

                if user:
                    latest_update = Update.query.filter_by(user_id=user.id).order_by(Update.timestamp.desc()).first()
                    if latest_update:
                        latest_skills = Skill.query.join(RegionSkill).filter(RegionSkill.update_id == latest_update.id).all()
                        latest_levels = {(skill.region_skill.region_name, skill.name): skill.level for skill in latest_skills}

                        for region_name, skills_data in parsed_data.items():
                            for skill_data in skills_data:
                                try:
                                    level = int(skill_data['Level'])
                                    if level <= 0 or level > 500:
                                        return render_template('paste_image.html', error_message="Skill levels must be between 1 and 500.", image_data=image_data, username=username)
                                    skill_data['Level'] = level
                                except ValueError:
                                    return render_template('paste_image.html', error_message="Skill levels must be valid integers.", image_data=image_data, username=username)

                                old_level = latest_levels.get((region_name, skill_data['Skill']), 0)
                                level_increase = level - old_level
                                if level_increase > 135:
                                    return render_template('paste_image.html', error_message="Level increase exceeds 35 for some skills.", image_data=image_data, username=username)
                else:
                    for region_name, skills_data in parsed_data.items():
                        for skill_data in skills_data:
                            try:
                                level = int(skill_data['Level'])
                                if level <= 0 or level > 500:
                                    return render_template('paste_image.html', error_message="Skill levels must be between 1 and 500.", image_data=image_data, username=username)
                            except ValueError:
                                return render_template('paste_image.html', error_message="Skill levels must be valid integers.", image_data=image_data, username=username)
                session['extracted_data'] = parsed_data
                return render_template('review_ocr.html', extracted_data=parsed_data, username=username)
            else:
                return f"Error: Unexpected data format from parser. Received type: {type(parsed_data)}"
        except Exception as e:
            return render_template(
                'paste_image.html',
                error_message=f"Error processing image: {e}",
                image_data=request.form.get('image_data', ''),
                username=session.get('game_username')
            )
    return render_template('paste_image.html')

@app.route('/save_ocr_data', methods=['POST'])
@login_required
def save_ocr_data():
    if request.method == 'POST':
        extracted_data = session.get('extracted_data')
        username = session.get('game_username')
        if extracted_data and username:
            try:
                parsed_data = extracted_data  # Data is already a Python dictionary
                user = User.query.filter_by(username=username).first()
                
                # Create user if they don't exist
                if not user:
                    user = User(username=username)
                    db.session.add(user)
                    db.session.flush()  # Get the user ID

                # Proceed to save the data
                update = Update(user_id=user.id)
                db.session.add(update)
                db.session.flush()

                for region_name, skills_data in parsed_data.items():
                    region_skill = RegionSkill(update_id=update.id, region_name=region_name)
                    db.session.add(region_skill)
                    db.session.flush()
                    
                    for skill_data in skills_data:
                        # Get the previous level for this skill
                        previous_skill = Skill.query.join(RegionSkill).join(Update)\
                            .filter(
                                Update.user_id == user.id,
                                RegionSkill.region_name == region_name,
                                Skill.name == skill_data['Skill']
                            )\
                            .order_by(Update.timestamp.desc())\
                            .first()
                            
                        # Only save if new level is >= previous level
                        if not previous_skill or skill_data['Level'] >= previous_skill.level:
                            skill = Skill(
                                region_skill_id=region_skill.id,
                                name=skill_data['Skill'],
                                level=skill_data['Level']
                            )
                            db.session.add(skill)
                        else:
                            # Log or handle the level decrease case
                            app.logger.warning(f"Level decrease detected for {skill_data['Skill']} in {region_name} for user {username}")
                db.session.commit()
                session.pop('extracted_data', None)  # Clear session data after saving
                return redirect(url_for('search', username=username))
            except Exception as e:
                return f"Error saving data: {str(e)}"
        return "Error: Missing data."

"""
@app.route('/ocr/<filename>')
def ocr_image(filename):
    image_path = os.path.join(app.config['IMAGE_FOLDER'], filename)
    try:
        #with open(image_path, 'rb') as f:
        #    image_data = f.read()

        parser = JsonOutputParser()
        prompt = "Extract the text table from this image only. Return it as a JSON object with keys: 'Rank', 'Name', and 'Level'. Do not include any other text or explanations."
        
        response = chat(
            model='llama3.2-vision',
            messages=[
                {
                    'role': 'user',
                    'content': prompt,
                    'images': [image_path],
                }
            ],
        )
        extracted_text = response['message']['content']
        print("Raw Response:", extracted_text)
        parsed_data = parser.parse(extracted_text)
        print("Parsed Data:", parsed_data)
        return render_template('ocr_results.html', parsed_data=parsed_data, image_filename=filename)
    except FileNotFoundError:
        return f"Image '{filename}' not found in the image folder."
    except Exception as e:
        return f"Error processing image: {e}"
"""


@app.route('/privacy')
def privacy_policy():
    return render_template('privacy.html')

@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form['username'])
        password = sanitize_input(request.form['password'])
        confirm_password = sanitize_input(request.form['confirm_password'])

        if not username or not password:
            return render_template('register.html', error_message="Username and password are required.")

        if username != request.form['username']:
            return render_template('register.html', error_message="Invalid characters in username.")

        if len(username) > 20:
            return render_template('register.html', error_message="Username must be 20 characters or less.")
        
        # Validate email format if username is an email
        if '@' in username:
            if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', username):
                return render_template('register.html', error_message="Invalid email format.")

        if len(password) < 8:
            return render_template('register.html', error_message="Password must be at least 8 characters long.")
        if password == username:
            return render_template('register.html', error_message="Password cannot be the same as username.")
        if not re.search(r'[A-Z]', password):
            return render_template('register.html', error_message="Password must contain at least one uppercase letter.")
        if not re.search(r'\d', password):
            return render_template('register.html', error_message="Password must contain at least one number.")
        if password != confirm_password:
            return render_template('register.html', error_message="Passwords do not match.")

        existing_user = AuthUser.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error_message="Username already exists.")

        if 'privacy_consent' not in request.form:
            return render_template('register.html', error_message="Please agree to the Privacy Policy.")
        # Hash the password and generate encryption key
        password_hash = generate_password_hash(password, method='scrypt')
        app.logger.debug(f"Generated password hash for new user: {password_hash}")
        
        new_user = AuthUser(
            username=username,
            password_hash=password_hash,
        )
        db.session.add(new_user)
        db.session.commit()
        
        app.logger.debug(f"Successfully registered new user: {username}")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = AuthUser.query.filter_by(username=username).first()
        if user:
            if user.is_banned:
                return render_template('login.html', error_message='This account has been banned.')
            
            # Enhanced debug logging
            print(f"Attempting login for user: {username}")
            print(f"Stored hash: {user.password_hash}")
            
            # SECURITY WARNING: Only log the password temporarily for debugging!
            print(f"Attempted password: {password}")
            
            check_result = check_password_hash(user.password_hash, password)
            print(f"Password check result: {check_result}")
            
            if check_result:
                session['user_id'] = user.id
                session['username'] = username  # Store original username in session
                session['game_username'] = user.decrypt_game_username_with_key()
                app.logger.debug(f"Login successful for user: {username}")
                return redirect(url_for('index')), 302

        return render_template('login.html', error_message='Invalid credentials')
    return render_template('login.html')



def admin_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if session.get('user_id') is None:
            return redirect(url_for('login'))
        user = db.session.get(AuthUser, session['user_id'])
        if not user or not user.is_admin:
            return redirect(url_for('index'))
        return view(**kwargs)
    return wrapped_view
"""
@app.route('/create_admin', methods=['POST'])
@csrf.exempt
def create_admin():
    # Only allow from localhost
    # REMOVE THIS ROUTE AFTER INITIAL ADMIN USER CREATION
    if request.remote_addr != '127.0.0.1':
        return "Unauthorized", 403
        
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return "Username and password required", 400
        
    existing_user = AuthUser.query.filter_by(username=username).first()
    if existing_user:
        return "User already exists", 400
        
    password_hash = generate_password_hash(password)
    new_user = AuthUser(
        username=username,
        password_hash=password_hash,
        is_admin=True
    )
    db.session.add(new_user)
    db.session.commit()
    return "Admin user created", 201
"""
@app.route('/logout')
def logout():
    # Clear session data
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('game_username', None)
    
    return redirect(url_for('index'))

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user_id = session.get('user_id')
    if user_id:
        user = db.session.get(AuthUser, user_id)
        if user:
            # Delete associated user data from the other database
            related_user = User.query.filter_by(username=session.get('username')).first()
            if related_user:
                # Delete all updates associated with the user
                Update.query.filter_by(user_id=related_user.id).delete()
                db.session.delete(related_user)

            # Immediately delete the AuthUser
            db.session.delete(user)
            db.session.commit()
            session.clear()  # Log the user out
            return redirect(url_for('index')), 302
    return redirect(url_for('index'))  # Redirect to index if user not found

@app.route('/link_game_username', methods=['POST'])
@login_required
def link_game_username():
    game_username = request.form.get('game_username')
    user_id = session.get('user_id')
    error_message = None
    success_message = None

    if game_username:
        # Decrypt existing game usernames for comparison
        all_users = AuthUser.query.filter(AuthUser.game_username != None).all()
        existing_usernames = [u.decrypt_game_username_with_key() for u in all_users if u.decrypt_game_username_with_key() is not None]

        # Check if game username is already linked to another account
        is_unique = True
        for existing_username in existing_usernames:
            if existing_username == game_username:
                is_unique = False
                if db.session.get(AuthUser, user_id).decrypt_game_username_with_key() != game_username:
                    break
                
        if not is_unique:
            return render_template(
                'settings.html',
                error_message="This game username is already linked to another account. Please choose a different username.",
                game_username=game_username)
        else:
            user = db.session.get(AuthUser, user_id)
            if user:
                user.game_username = Fernet(app.app_wide_encryption_key.encode()).encrypt(game_username.encode()).decode()
                db.session.commit()
                session['game_username'] = game_username
                success_message = "Game username linked successfully."
            else:
                error_message = "User not found. Please try logging out and back in."
    else:
        error_message = "Game username cannot be empty."

    return render_template('settings.html', error_message=error_message, success_message=success_message, game_username=game_username)

@app.route('/unlink_game_username', methods=['POST'])
@login_required
def unlink_game_username():
    user_id = session.get('user_id')
    user = db.session.get(AuthUser, user_id)
    if user:
        user.game_username = None
        db.session.commit()
        session.pop('game_username', None)
        return render_template('settings.html', success_message="Game username unlinked successfully.")
    return render_template('settings.html', error_message="User not found.")

@app.route('/admin_unlink_game_username/<int:user_id>', methods=['POST'])
@admin_required
def admin_unlink_game_username(user_id):
    user = db.session.get(AuthUser, user_id)
    if user:
        if user.game_username:
            user.game_username = None
            db.session.commit()
            return redirect(url_for('admin_dashboard'))
        else:
            return "No game username to unlink.", 400
    return "User not found.", 404

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    old_password = request.form['old_password']
    new_password = request.form['new_password']
    user_id = session.get('user_id')
    if user_id:
        user = db.session.get(AuthUser, user_id)
        if user and check_password_hash(user.password_hash, old_password):
            if len(new_password) < 6:
                return render_template('settings.html', error_message="New password must be at least 6 characters long.")
            user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            return render_template('settings.html', success_message="Password updated successfully.")
        else:
            return render_template('settings.html', error_message="Incorrect old password.")
    return redirect(url_for('login'))

@app.route('/ban_user/<int:user_id>', methods=['POST'])
@admin_required
def ban_user(user_id):
    app.logger.info(f"Attempting to ban user ID: {user_id}")
    user = db.session.get(AuthUser, user_id)
    if user:
        if user.is_admin:
            app.logger.info(f"User {user.username} is an admin and cannot be banned.")
        else:
            app.logger.info(f"User found: {user.username}, is_admin: {user.is_admin}. Proceeding to ban.")
            user.is_banned = True
            db.session.commit()
            app.logger.info(f"User {user.username} banned successfully.")
    else:
        app.logger.info(f"User with ID {user_id} not found.")
    return redirect(url_for('admin_dashboard'))

@app.route('/unban_user/<int:user_id>', methods=['POST'])
@admin_required
def unban_user(user_id):
    user = db.session.get(AuthUser, user_id)
    if user and not user.is_admin:
        user.is_banned = False
        db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    users = AuthUser.query.all()
    # CSRF token is needed for the forms in the template
    return render_template('admin.html', users=users)

@app.route('/export_data')
@login_required
def export_data():
    user_id = session.get('user_id')
    user = db.session.get(User, user_id)
    if user:
        updates = Update.query.filter_by(user_id=user.id).order_by(Update.timestamp.asc()).all()
        user_data = {
            "username": user.username,
            "updates": []
        }
        for update in updates:
            update_data = {
                "timestamp": update.timestamp.isoformat(),
                "regions": {}
            }
            for region_skill in update.region_skills:
                update_data["regions"][region_skill.region_name] = [{"skill": skill.name, "level": skill.level} for skill in region_skill.skills]
            user_data["updates"].append(update_data)
        return jsonify(user_data)
    else:
        return "User not found", 404


def is_user_banned():
    user_id = session.get('user_id')
    if user_id:
        user = db.session.get(AuthUser, user_id)
        return user and user.is_banned
    return False

@app.before_request
def check_banned_status():
    if 'user_id' in session and is_user_banned():
        session.clear()
        # Optionally, redirect to a specific banned page
        return redirect(url_for('login'), 303)

@app.errorhandler(RateLimitExceeded)
def handle_rate_limit_exceeded(e):
    return render_template('error.html', error_message="Too many requests. Please try again later."), 429

@app.errorhandler(Exception)
def handle_exception(e):
    # Log the error for debugging
    app.logger.error(f"An error occurred: {str(e)}")
    # Return a generic error message to the user
    return render_template('error.html'), 500

if DEBUG_MODE:
    app.config.update(SERVER_NAME='localhost:5001', PREFERRED_URL_SCHEME='http')
else:
    # Production settings
    app.config.update(SERVER_NAME='brighterprogress.dson.cloud', PREFERRED_URL_SCHEME='https') # Replace with your domain

if __name__ == '__main__':
    # Create images folder if it doesn't exist
    if not os.path.exists(app.config['IMAGE_FOLDER']):
        os.makedirs(app.config['IMAGE_FOLDER'])
    
    if DEBUG_MODE:
        app.run(host='localhost', port=5001, debug=DEBUG_MODE)
    else:
        from gevent.pywsgi import WSGIServer
        http_server = WSGIServer(('', 5050), app)
        http_server.serve_forever()

@app.route('/static/css/<path:filename>')
def custom_static(filename):
    return send_from_directory(os.path.join(app.root_path, 'static', 'css'), filename)

def encode_image_base64(image_data):
    return base64.b64encode(image_data).decode('utf-8')
