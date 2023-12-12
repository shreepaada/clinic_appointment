from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from passlib.hash import sha256_crypt
from threading import Lock

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    appointments = db.relationship('Appointment', backref='user', lazy=True)

# Appointment Model
class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time = db.Column(db.String(100))
    doctor = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

with app.app_context():
    db.create_all()

# Define fixed time slots
time_slots = ['9:00', '9:30', '10:00', '10:30', '11:00', '11:30', '12:00', '12:30', '13:00', '13:30', '14:00', '14:30']

# Initialize doctors' availability
doctors = ['Doctor 1', 'Doctor 2', 'Doctor 3', 'Doctor 4']
lock = Lock()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and sha256_crypt.verify(password, user.password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        hashed_password = sha256_crypt.hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        selected_doctor = request.form['doctor']
        appointment_time = request.form['appointment_time']
        action = request.form['action']

        with lock:  # Synchronization lock
            existing_appointment = Appointment.query.filter_by(time=appointment_time, doctor=selected_doctor, user_id=current_user.id).first()
            if action == 'Book':
                if not existing_appointment:
                    new_appointment = Appointment(time=appointment_time, doctor=selected_doctor, user_id=current_user.id)
                    db.session.add(new_appointment)
                    db.session.commit()
                    flash('Appointment booked successfully!', 'success')
                else:
                    flash('Appointment time not available or already booked.', 'error')
            elif action == 'Cancel':
                if existing_appointment:
                    db.session.delete(existing_appointment)
                    db.session.commit()
                    flash('Appointment cancelled successfully!', 'info')
                else:
                    flash('No such appointment to cancel.', 'error')

    user_appointments = Appointment.query.filter_by(user_id=current_user.id).all()
    available_slots = {doctor: [slot for slot in time_slots if not Appointment.query.filter_by(time=slot, doctor=doctor, user_id=current_user.id).first()] for doctor in doctors}
    return render_template('dashboard.html', user_appointments=user_appointments, available_slots=available_slots, doctors=doctors)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
