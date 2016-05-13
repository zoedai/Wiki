from google.appengine.ext import db
import jinja2
import os
import main

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
		if u and main.verify_pw(name, pw, u.password):
			return u

def users_key(group = 'default'):
	return db.Key.from_path('users', group)



class Wikiurl(db.Model):
	url = db.StringProperty(required = True)
	

class Wikipost(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	author = db.ReferenceProperty(User, required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	# url = db.ReferenceProperty(Wikiurl, required = True)
	# last_modified = db.DateTimeProperty(auto_now = True)

	def as_dict(self):
	    time_fmt = '%c'

	    d = {'subject': subject,
	         'content': self.content,
	         'created': self.created.strftime(time_fmt),
	         'author': self.author.username,
	         }
	    return d

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')		
		return main.render_str("wiki_post.html", p = self)
        

