from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps


app= Flask(__name__)

#config mysql
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'myflaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

#initialize mysql
mysql = MySQL(app)

Articles = Articles()

#Index
@app.route('/')
def index():
	return render_template('index.html')

#About 
@app.route('/about')
def about():
	return render_template('about.html')

#Articles
@app.route('/articles')
def articles():
	return render_template('articles.html', articles = Articles)

#Single Article
@app.route('/article/<string:id>/')
def article(id):
	return render_template('articles.html', id = id)

#Register Form Class
class RegisterForm(Form):
	name = StringField('Name', [validators.Length(min=1, max=50)])
	username=StringField('username', [validators.Length(min=4, max=25)])
	email=StringField('Email', [validators.Length(min=6, max=50)])
	password=PasswordField('Password', [
		validators.DataRequired(),
		validators.EqualTo('confirm', message='Passwords Do not Match')
	])
	confirm=PasswordField('confirm Password')

#User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
	form=RegisterForm(request.form)
	if request.method == 'POST' and form.validate():
		name = form.name.data
		email = form.email.data
		username = form.username.data
		password = sha256_crypt.encrypt(str(form.password.data))

		#create cursor
		cur = mysql.connection.cursor()

		#Execute query
		cur.execute("INSERT INTO users(name, email, username, password)VALUES(%s, %s, %s, %s)",(name, username, email, password))

		#commit to DB
		mysql.connection.commit()

		#close connection
		cur.close()

		flash("You are now registered and can login", 'success')

		redirect(url_for('index'))


		return render_template('register.html', form=form)
	return render_template('register.html', form=form)

#user login
@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		#Get form fields
		username = request.form['username']
		password_candidate = request.form['password']

		#Create a cursor
		cur = mysql.connection.cursor()

		#Get user by username
		result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

		if result > 0:
			#Get stored hash
			data = cur.fetchone()
			password = data['password']

			#Compare the passwords
			if sha256_crypt.verify(password_candidate, password):
				app.logger.info('Password Matched')

				#passed
				session['logged_in'] = True
				session['username'] = username

				flash('You are Now logged in', 'success')
				return redirect(url_for('dashboard'))
			else:
				error = 'Invalid Login'
				return render_template('login.html', error=error)

			#close connection
			cur.close()

		else:
			error = 'Username Not Found'
			return render_template('login.html', error=error)

	return render_template('login.html')


#Check if user logged in
def is_logged_in(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' in session:
			return f(*args, **kwargs)
		else:
			flash('Unauthorised Please Login', 'danger')
			return redirect(url_for('login'))
	return wrap

#Logout
@app.route('/logout')
def logout():
	session.clear()
	flash('You are now logged out', 'success')
	return redirect(url_for('login'))

#Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
	return render_template('dashboard.html')


if __name__ == '__main__':
	app.secret_key = 'secret123'
	app.run(debug=True)