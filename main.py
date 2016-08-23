#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import hashlib
import hmac
import os
import random
import re
import string

import jinja2
import webapp2
from google.appengine.ext import db

SECRET = 'imsosecret'

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
COOKIE_RE = re.compile(r'.+=;\s*Path=/')

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    val = h.split(',')[1]
    return h == make_pw_hash(name, pw, val)


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


def valid_username(username):
    return USER_RE.match(username)


def valid_password(password):
    return PASSWORD_RE.match(password)


def valid_email(email):
    return EMAIL_RE.match(email)


def valid_cookie(cookie):
    return cookie and COOKIE_RE.match(cookie)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    @staticmethod
    def render_str(template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class Blog(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


class SignupPage(Handler):
    def get(self):
        form_username = self.request.get('username')
        form_password = self.request.get('password')
        form_verify = self.request.get('verify')
        form_email = self.request.get('email')
        self.render("signup.html", username=form_username, password=form_password, verify_password=form_verify,
                    email=form_email)

    def post(self):
        form_username = self.request.get('username')
        form_password = self.request.get('password')
        form_verify = self.request.get('verify')
        form_email = self.request.get('email')

        username = bool(valid_username(form_username))
        password = bool(valid_password(form_password))
        email = True
        if form_email:
            email = bool(valid_email(form_email))

        username_error = None if username else "That's not a valid username."
        password_error = None if password else "That wasn't a valid password."
        verify_password_error = None if form_password == form_verify else "Your passwords didn't match."
        email_error = None if email else "That's not a valid email."

        if form_password != form_verify or not (username and password and email):
            self.render("signup.html",
                        username=form_username,
                        password=form_password,
                        verify_password=form_verify,
                        email=form_email,
                        verify_password_error=verify_password_error,
                        username_error=username_error,
                        password_error=password_error,
                        email_error=email_error)
        else:
            self.response.headers.add_header('Set-Cookie', 'user=%s' % str(form_username))
            self.response.headers.add_header('Set-Cookie', 'password=%s' % str(form_password))
            self.redirect("/blog/welcome")


class LoginPage(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        form_username = self.request.get('username')
        form_password = self.request.get('password')

        username_cookie = self.request.cookies.get('user')
        password_cookie = self.request.cookies.get('password')

        username = bool(valid_username(form_username))
        password = bool(valid_password(form_password))

        auth_check = (form_username == username_cookie and form_password == password_cookie)

        username_error = None if username else "Invalid login1"
        password_error = None if password else "Invalid login2"

        auth_check_error = None if auth_check else "Invalid login"

        if not (username and password):
            self.render("login.html",
                        username=form_username,
                        password=form_password,
                        username_error=username_error,
                        password_error=password_error)
        elif not auth_check:
            self.render("login.html",
                        username=form_username,
                        password=form_password,
                        auth_check_error=auth_check_error)
        else:
            self.redirect("/blog/welcome")


class MainPage(Handler):
    def render_front(self, subject='', content='', error=''):
        posts = db.GqlQuery('SELECT * FROM Blog ORDER BY created DESC')
        self.render("blog.html", error=error, subject=subject, content=content, posts=posts)

    def get(self):
        self.render_front()


class NewPostHandler(Handler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            a = Blog(subject=subject, content=content)
            a.put()

            self.redirect("/blog/%s" % a.key().id())
        else:
            error = "Subject and content are required"
            self.render("newpost.html", subject=subject, content=content, error=error)


class PostHandler(Handler):
    def get(self, post_id):
        post = Blog.get_by_id(int(post_id))

        if not post:
            self.error(404)
            return

        self.render("post.html", post=post)


class LogoutPage(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user=')
        self.response.headers.add_header('Set-Cookie', 'password=')
        self.redirect("/blog/signup")


class WelcomeHandler(Handler):
    def get(self):
        username = self.request.cookies.get('user')
        self.render("success.html", username=username)


app = webapp2.WSGIApplication(
    [('/blog/signup', SignupPage), ('/blog/welcome', WelcomeHandler), ('/blog/login', LoginPage),
     ('/blog/logout', LogoutPage), ('/blog', MainPage),
     ('/blog/newpost', NewPostHandler),
     (r'/blog/(\d+)', PostHandler)],
    debug=True)
