from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
# from flask_mail import Mail, Message
# from itsdangerous import URLSafeTimedSerializer, SignatureExpired
# from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps


app= Flask(__name__)
# app.config.from_pyfile('config.cfg')
# mail = Mail(app)
# s= URLSafeTimedSerializer('This is a secret')

#config mysql
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'myflaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

#initialize mysql
mysql = MySQL(app)

# Articles = Articles()

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
	# Create Cursor
	cur = mysql.connection.cursor()

	# Get Articles
	result = cur.execute("SELECT * FROM articles")

	articles = cur.fetchall()

	if result > 0:
		return render_template('articles.html', articles=articles)
	else:
		msg = 'No Articles Found'
		return render_template('articles.html', msg=msg)

	# Close Connection
	cur.close()
	

#Single Article
@app.route('/articles/<string:id>/')
def article(id):
	# Create Cursor
	cur = mysql.connection.cursor()

	# Get Article
	result = cur.execute("SELECT * FROM articles WHERE id= %s", [id])

	article = cur.fetchone()
	return render_template('article.html', article = article )

#Register Form Class
class RegisterForm(Form):
	name = StringField('Name', [validators.Length(min=1, max=50)])
	username=StringField('Username', [validators.Length(min=4, max=25)])
	email=StringField('Email', [validators.Length(min=6, max=50)])
	password=PasswordField('Password', [
		validators.DataRequired(),
		validators.EqualTo('confirm', message='Passwords Do not Match')
	])
	confirm=PasswordField('Confirm Password')

#User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
	form=RegisterForm(request.form)
	if request.method == 'POST' and form.validate():
		name = form.name.data
		username = form.username.data
		email = form.email.data
		password = sha256_crypt.encrypt(str(form.password.data))

		#create cursor
		cur = mysql.connection.cursor()

		#Execute query
		cur.execute("INSERT INTO users(name, username, email, password)VALUES(%s, %s, %s, %s)",(name, username, email, password))

		#Confirm the Email Used for registration whether valid
		# email = request.form['email']
		# token = s.dumps(email, salt='email-confirm')

		# msg = Message('Confirm Email',sender='paulmucimah@gmail.com', recipients=[email])
		# link = url_for('confirm_email', token=token, external=True)
		# msg.body = 'Your confirmation link is {}'.format(link)
		# mail.send(msg)

		#commit to DB
		mysql.connection.commit()

		#close connection
		cur.close()

		flash("You are now registered and can login to confirm your Email", 'success')

		redirect(url_for('index'))


		return render_template('register.html', form=form)
	return render_template('register.html', form=form)

# Confirm Email
	# @app.route('/confirm_email/<token>')
	# def confirm_email(token):
	# 	try:
	# 		email = s.loads(token, salt='email-confirm', max_age=3600)
	# 	except SignatureExpired:
	# 		return '<h1>The link has already Expired</h1>'
	# 	return "The Email has been confirmed"


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
	# Create Cursor
	cur = mysql.connection.cursor()

	# Get Articles
	result = cur.execute("SELECT * FROM articles")

	articles = cur.fetchall()

	if result > 0:
		return render_template('dashboard.html', articles=articles)
	else:
		msg = 'No Articles Found'
		return render_template('dashboard.html', msg=msg)

	# Close Connection
	cur.close()

# Article Form Class
class ArticleForm(Form):
	title= StringField('Title', [validators.Length(min=1, max=200)])
	body=TextAreaField('Body', [validators.Length(min=30)])

# Add Article
@app.route('/add_article', methods=['GET','POST'])
@is_logged_in
def add_article():
	form = ArticleForm(request.form)
	if request.method == 'POST' and form.validate():
		title = form.title.data
		body = form.body.data

		# Create Cursor
		cur = mysql.connection.cursor()

		# Execute
		cur.execute("INSERT INTO articles(title, body, author) VALUES(%s, %s, %s)",(title, body, session['username']))

		# Commit to DB
		mysql.connection.commit()

		# Close Connection
		cur.close()

		flash("Article Created", 'success')

		return redirect(url_for('dashboard'))

	return render_template('add_article.html', form=form)


# Edit Article
@app.route('/edit_article/<string:id>', methods=['GET','POST'])
@is_logged_in
def edit_article(id):
	# Create Cursor
	cur = mysql.connection.cursor()

	# Get article by id 
	result = cur.execute("SELECT * FROM articles WHERE id= %s", [id])

	article = cur.fetchone()

	# Get Form
	form = ArticleForm(request.form)

	# Populate Article Form Fields
	form.title.data = article['title']
	form.body.data = article['body']

	if request.method == 'POST' and form.validate():
		title = request.form['title']
		body = request.form['body']

		# Create Cursor
		cur = mysql.connection.cursor()

		# Execute
		cur.execute ("UPDATE articles SET title=%s, body=%s WHERE id=%s",(title, body, id))

		# Commit to DB
		mysql.connection.commit()

		# Close Connection
		cur.close()

		flash("Article Updated", 'success')

		return redirect(url_for('dashboard'))

	return render_template('edit_article.html', form=form)


# Delete Article
@app.route('/delete_article/<string:id>', methods=['POST'])
@is_logged_in
def delete_article(id):
	# Create Cursor
	cur = mysql.connection.cursor()

	# Execute
	cur.execute("DELETE FROM articles WHERE id = %s", [id])

	# Commit to DB
	mysql.connection.commit()

	# Close Connection
	cur.close()

	flash("Article Deleted", 'success')

	return redirect(url_for('dashboard'))

if __name__ == '__main__':
	app.secret_key = 'secret123'
	app.run(debug=True)