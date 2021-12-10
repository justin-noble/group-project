import json
import re
import sqlite3

from urllib.parse import unquote
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bootstrap import Bootstrap

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, TextAreaField
from wtforms.validators import InputRequired

conn = sqlite3.connect('rmc.sqlite', check_same_thread=False)


def setup():
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS `users` (
            user_id INTEGER PRIMARY KEY,
            email TEXT, 
            username TEXT, 
            password TEXT,
            UNIQUE(email)
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS `courses` (
            course_id TEXT,
            department TEXT,
            requirements TEXT,
            title TEXT,
            UNIQUE(course_id, department)
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS `teachers` (
            course_id TEXT,
            name TEXT,
            section TEXT,
            UNIQUE(course_id, name, section)
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS `course_reviews` (
            reviewer INTEGER,
            course_id TEXT,
            teacher TEXT,
            review TEXT,
            UNIQUE(reviewer, course_id, teacher)
        );
    """)

    courses = json.load(open('static/data.json'))
    for department in courses:
        for course in courses[department]:
            cursor.execute('INSERT OR IGNORE INTO courses (course_id, department, requirements, title) VALUES (?, ?, ?, ?)',
                           (course['number'], department, '', course['title']))
            if "teachers" in course and len(course['teachers']['classes']) > 0:
                for teacher in course['teachers']['classes']:
                    cursor.execute('INSERT OR IGNORE INTO teachers (course_id, name, section) VALUES (?, ? ,?)',
                                   (course['number'], teacher['instructor']['displayname'], teacher['section']))

    conn.commit()

setup()
app = Flask(__name__)
boostrap = Bootstrap(app)

app.secret_key = 'adasdasdas4856das56d4as6'

setup()


class RegisterForm(FlaskForm):
    username = StringField('Username: ', validators=[InputRequired()])
    email = EmailField('Email: ', validators=[InputRequired()])
    password = PasswordField('Password: ', validators=[InputRequired()])
    submit = SubmitField('Register!')

class LoginForm(FlaskForm):
    username = StringField('Username: ', validators=[InputRequired()])
    password = PasswordField('Password: ', validators=[InputRequired()])
    submit = SubmitField('Register!')

class ReviewForm(FlaskForm):
    review = TextAreaField('Review', validators=[InputRequired()])
    submit = SubmitField('Submit Review!')

class SearchForm(FlaskForm):
    search = StringField('', validators=[InputRequired()])
    submit = SubmitField('Search!')


@app.route('/')
def home():  # put application's code here
    return render_template('home.html')


@app.route('/search', methods=['GET', 'POST'])
def search():
    form = SearchForm()
    courses = []
    if request.method == 'POST' and form.validate_on_submit():
        search = form.search.data
        cursor = conn.cursor()
        courses = cursor.execute("SELECT * FROM courses WHERE course_id LIKE ? OR title LIKE ?", ('%'+search+'%','%'+search+'%')).fetchall()
    return render_template('search.html', form=form, courses=courses)


@app.route('/course/<course_id>')
def course(course_id):
    cursor = conn.cursor()
    course = cursor.execute('SELECT * FROM courses WHERe course_id=?', (course_id,)).fetchone()
    teachers = cursor.execute('SELECT * FROM teachers WHERE course_id=?', (course_id,)).fetchall()
    return render_template('course.html', course=course, teachers=teachers)

@app.route('/review/<course_id>/<name>', methods=['GET', 'POST'])
def review(course_id, name):
    form = ReviewForm()
    cursor = conn.cursor()
    if request.method == 'POST' and form.validate_on_submit():
        review = form.review.data
        cursor.execute('REPLACE INTO course_reviews (reviewer, course_id, teacher, review) VALUES (?, ?, ?, ?)',
                       (session['id'], course_id, name, review))
        conn.commit()

    course = cursor.execute('SELECT * FROM courses WHERe course_id=?', (course_id,)).fetchone()
    teacher = cursor.execute('SELECT * FROM teachers WHERE course_id=? AND name=?', (course_id, unquote(name))).fetchone()
    reviews = cursor.execute('SELECT * FROM course_reviews INNER JOIN users ON course_reviews.reviewer=users.user_id WHERe course_id=? AND teacher=?', (course_id, unquote(name))).fetchall()
    return render_template('review.html', course=course, teacher=teacher, reviews=reviews, form=form)

@app.route('/courses')
def courses():
    cursor = conn.cursor()
    data = cursor.execute('SELECT * FROM courses').fetchall()
    courses = {}
    for course in data:
        if course[1] in courses:
            courses[course[1]].append(course)
        else:
            courses[course[1]] = [course]

    return render_template('courses.html', courses=courses)

@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
    session.pop('id', None)
    session.pop('username', None)
    # Redirect to login page
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():  # put application's code here
    # Check if user is loggedin
    if 'id' in session and session['id']:
        # User is loggedin show them the home page
        return redirect(url_for('home'))

    # Output message if something goes wrong...
    msg = ''
    form = LoginForm()
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and form.validate_on_submit():
        # Create variables for easy access
        username = form.username.data
        password = form.password.data
        # Check if user exists using MySQL
        # conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute('SELECT user_id, username, password FROM users WHERE username = ?', (username,))
        # Fetch one record and return result
        user = cursor.fetchone()
        # If user exists in users table in out database
        if user and check_password_hash(user[2], password):
            # Create session data, we can access this data in other routes
            session['id'] = user[0]
            session['username'] = user[1]
            # Redirect to home page
            return redirect(url_for('home'))
        else:
            # user doesnt exist or username/password incorrect
            msg = 'Incorrect username/password! :/'

    # Show the login form with message (if any)
    return render_template('login.html', msg=msg, form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():  # put application's code here
    # Output message if something goes wrong...
    msg = ''
    form = RegisterForm()
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if form.validate_on_submit():
        # Create variables for easy access
        email = form.email.data
        username = form.username.data
        password = form.password.data
        hash = generate_password_hash(password)

        # Check if user exists using MySQL
        # conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        # If user exists show error and validation checks
        if user:
            msg = 'Username or Email already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            # user doesnt exists and the form data is valid, now insert new user into users table
            cursor.execute('INSERT INTO users (email, username, password) VALUES (?, ?, ?)',
                           (email, username, hash,))
            conn.commit()
            return redirect(url_for('login'))
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'
    # Show registration form with message (if any)
    return render_template('register.html', msg=msg, form=form)

if __name__ == '__main__':
    app.run()
