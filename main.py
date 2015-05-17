
#
import os
import re
import webapp2
import jinja2
# import bcrypt
import hashlib
import hmac
import random
import string
import json

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
	extensions = ['jinja2.ext.autoescape'],
	autoescape = True)

secret = 'starsmydestination'
PAGETITLE = "Blog 1.5"
nav_bar_list = [{"href": "/blog", "caption":"Home"},
{"href": "/blog/newpost", "caption":"New Post"},
]


def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
		params['sitename'] = PAGETITLE
		params['nav_bar_list'] = nav_bar_list
		params['user'] = self.user
		return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
    	cookie_val = encrypt_cookie(val)
    	self.response.set_cookie(name, cookie_val, path='/')

    def read_secure_cookie(self, name):
    	cookie_val = self.request.cookies.get(name)
    	return cookie_val and verify_cookie(cookie_val)

    def login(self, user):
    	self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
    	self.response.delete_cookie('user_id')

    def render_json(self, d):
	    json_txt = json.dumps(d)
	    self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
	    self.write(json_txt)

    # copy
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'


class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def as_dict(self):
	    time_fmt = '%c'
	    d = {'subject': self.subject,
	         'content': self.content,
	         'created': self.created.strftime(time_fmt),
	         'last_modified': self.last_modified.strftime(time_fmt)}
	    return d

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self)



	    

#### user stuff
def make_salt():
	return "".join(random.choice(string.letters) for _ in range(8))
	
def make_secure_pw(s, salt= None):
	if not salt:
		salt = make_salt()
	return '%s|%s'%(salt, hashlib.sha256(s+salt).hexdigest())

def verify_pw(name, pw, hashed):
	salt = hashed.split('|')[0]
	return make_secure_pw(name+pw, salt) == hashed

def encrypt_cookie(val):
	return '%s|%s' % (val, hmac.new(str(val),secret).hexdigest())

def verify_cookie(value):
	val = value.split('|')[0]
	if value == encrypt_cookie(val):
		return val




class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('username =', name).get()
		return u

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and verify_pw(name, pw, u.password):
			return u

def users_key(group = 'default'):
	return db.Key.from_path('users', group)

class PostHandler(Handler):
	def get(self, post_id):
		p = Post.get_by_id(int(post_id))

		if not p:
			self.error(404)
			return
		if self.format == 'html':
			self.render("permlink.html", p = p)
		else:
			self.render_json(p.as_dict())

class BlogFront(Handler):
	def get(self):
		posts = db.GqlQuery("SELECT * FROM Post "
						   "ORDER BY created DESC")
		if self.format == 'html':
			self.render("main.html", posts = posts, currentPage = "Home")
		else:
			self.render_json([p.as_dict() for p in posts])

class NewPost(Handler):
	# def render_newpost(self, title = "", 
	# 	content = "", error = ""):
	# 	self.render("newpost.html", pagetitle = "New Post", 
	# 		title = title, content = content, error = error)
	def get(self):
		self.render("newpost.html", pagetitle = "Write a new post!", currentPage = "New Post")

	def post(self):
		title = self.request.get("subject")
		content = self.request.get("content")

		if title and content:
			a = Post(subject = title, content = content)
			a.put()
			self.redirect("/blog/"+str(a.key().id()))
		else:
			error = "we need both a title and some words!"
			self.render_newpost(title, content, error)

# some validation (from teacher)
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)
    
class SignUp(Handler):
	def post(self):
		has_error = False
		self.username = self.request.get("username")
		self.password = self.request.get("password")
		self.verify = self.request.get("verify")
		self.email = self.request.get("email")

		params = dict(username = self.username,
			email = self.email)

		if valid_username(self.username):
			if db.GqlQuery("SELECT * FROM User WHERE username = :1", self.username).get():
				params['error_username'] = "user already exists!"
				has_error = True
		else:
			params['error_username'] = "not a valid username"
			has_error = True

		if not valid_password(self.password):
			params['error_password'] = "not a valid password"
			has_error = True
		elif self.password != self.verify:
			params['error_verify'] =  "password didn't match"
			has_error = True

		if self.email and not valid_email(self.email):
			params['error_email'] = "not a valid email"
			has_error = True

		if has_error:
			self.get(**params)
		else:
			hashed = make_secure_pw(self.username+self.password)
			usr = User(username = self.username,
			 password = hashed, email = self.email,
			 parent = users_key())
			usr.put()
			self.login(usr)
			self.redirect('/blog/welcome?user='+self.username)


	def get(self, **kw):
		self.render("signup.html", **kw)


class SignIn(Handler):
	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		
		u = User.login(username, password)
		if u:
			self.login(u)
			self.redirect('/blog')
		else:
			self.get("invalid user name or password")

	def get(self, error = ""):
		self.render("login.html", currentPage = "Log in", error = error)


class Welcome(Handler):
	def get(self):
		user = self.request.get("user")
		self.write("Welcome, %s!" % user)

class LogOut(Handler):
	def get(self):
		self.logout()
		self.redirect('/blog')

			


app = webapp2.WSGIApplication([
    # ('/blog', BlogHandler),
    ('/blog/newpost', NewPost),
    ('/blog/?(?:\.json)?', BlogFront),
    ('/blog/([0-9]+)(?:\.json)?', PostHandler),
    ('/blog/signup', SignUp),
    ('/blog/welcome',Welcome),
    ('/blog/login', SignIn),
    ('/blog/logout', LogOut),
    # (r'/(\d+)', PostHandler)
], debug=True)
