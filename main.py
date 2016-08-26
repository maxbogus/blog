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

SECRET = 'fghjfhgl6lk5jl4k5jglf9559'

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
    return not email or EMAIL_RE.match(email)


def valid_cookie(cookie):
    return cookie and COOKIE_RE.match(cookie)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        params['logged'] = self.read_secure_cookie('user_id')
        params["user"] = self.user
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def check_restricted_zone(self):
        logged = self.read_secure_cookie('user_id')
        user_name = self.read_secure_cookie('user_login')
        if not logged:
            self.redirect('/blog/login')
        return user_name

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))
        self.set_secure_cookie('user_login', str(user.name))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.response.headers.add_header('Set-Cookie', 'user_login=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(), name=name, pw_hash=pw_hash, email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Blog(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    liked_by = db.ListProperty(str)
    comments = db.ListProperty(str, indexed=False, default=[])
    deleted = db.BooleanProperty(default=False)
    author = db.StringProperty(required=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @property
    def comments(self):
        return Comment.all().filter("post = ", str(self.key().id()))


class Comment(db.Model):
    comment = db.StringProperty(required=True)
    post = db.StringProperty(required=True)
    author = db.StringProperty(required=True)
    #
    # @classmethod
    # def render(self):
    #     self.render("comment.html")


class SignupPage(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        form_username = self.request.get('username')
        form_password = self.request.get('password')
        form_verify = self.request.get('verify')
        form_email = self.request.get('email')

        params = dict(username=form_username, email=form_email)

        if not valid_username(form_username):
            params['username_error'] = "That's not a valid username."
            have_error = True

        if not valid_password(form_password):
            params['password_error'] = "That wasn't a valid password."
            have_error = True
        elif form_password != form_verify:
            params['verify_password_error'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(form_email):
            params['email_error'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render("signup.html",
                        **params)
        else:
            u = User.by_name(form_username)
            if u:
                params['username_error'] = 'That user already exists.'
                self.render("signup.html",
                            **params)
            else:
                u = User.register(form_username, form_password, form_email)
                u.put()

                self.login(u)
                self.redirect("/blog/welcome")


class LoginPage(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect("/blog/welcome")
        else:
            error = 'Invalid login'
            self.render('login.html', error=error)


class MainPage(Handler):
    def render_front(self, subject='', content='', error=''):
        posts = db.GqlQuery('SELECT * FROM Blog WHERE deleted=false ORDER BY created DESC')
        self.render("blog.html", error=error, subject=subject, content=content, posts=posts)

    def get(self):
        self.render_front()


class NewPostHandler(Handler):
    def get(self):
        self.check_restricted_zone()
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.request.get("author")

        if subject and content:
            a = Blog(subject=subject, content=content, author=author, liked_by=[])
            a.put()

            self.redirect("/blog/%s" % a.key().id())
        else:
            error = "Subject and content are required"
            self.render("newpost.html", subject=subject, content=content, error=error)


class PostHandler(Handler):
    def get(self, post_id):
        post = Blog.get_by_id(int(post_id))
        options = self.request.get('options')

        if not post:
            self.error(404)
            return

        if post.deleted:
            self.error(404)
            return

        self.render("post.html", post=post, options=options)

    def post(self, post_id):
        post = Blog.get_by_id(int(post_id))
        user = User.by_id(self.user)
        self.render("post.html", post=post, user=user)


class PostEditHandler(Handler):
    def get(self, post_id):
        self.check_restricted_zone()
        post = Blog.get_by_id(int(post_id))
        subject = post.subject
        content = post.content
        edit = True

        if not post:
            self.error(404)
            return

        if post.deleted:
            self.error(404)
            return

        self.render("newpost.html", subject=subject, content=content, edit=edit, post=post)

    def post(self, post_id):
        post = Blog.get_by_id(int(post_id))
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            post.subject = subject
            post.content = content
            post.put()

            self.redirect("/blog/%s" % post.key().id())
        else:
            error = "Subject and content are required"
            self.render("newpost.html", subject=subject, content=content, error=error)


class PostDeleteHandler(Handler):
    def get(self, post_id):
        self.check_restricted_zone()
        self.render("choose.html")

    def post(self, post_id):
        post = Blog.get_by_id(int(post_id))
        opt = self.request.get('optradio')

        if opt == "Yes":
            post.deleted = True
            post.put()

            self.redirect("/blog")
        else:
            self.redirect("/blog/delete/%s" % post_id)


class PostLikeHandler(Handler):
    def get(self, post_id):
        self.check_restricted_zone()
        post = Blog.get_by_id(int(post_id))
        author = post.author
        user = self.request.get('author')
        if author == user or user in post.liked_by:
            self.redirect("/blog/%s" % post_id)
        else:
            post.liked_by.append(user)
            post.put()
            self.redirect("/blog")


class LogoutPage(Handler):
    def get(self):
        self.logout()
        self.redirect("/blog/signup")


class WelcomeHandler(Handler):
    def get(self):
        if self.user:
            self.render("success.html", username=self.user.name)
        else:
            self.redirect("/blog/signup")


class NewComment(Handler):
    def get(self, post_id):
        self.check_restricted_zone()
        post = Blog.get_by_id(int(post_id))
        subject = post.subject
        content = post.content
        self.render("newcomment.html",
                    subject=subject,
                    content=content,
                    pkey=post.key())

    def post(self, post_id):
        self.check_restricted_zone()
        post = Blog.get_by_id(int(post_id))
        if not post:
            self.error(404)
            return
        comment = self.request.get("comment")
        author = self.request.get('author')

        if comment:
            c = Comment(comment=comment, post=post_id, parent=self.user.key(), author=author)
            c.put()
            self.redirect("/blog")
        else:
            error = "please comment"
            self.render(
                "post.html",
                post=post,
                error=error)


class EditComment(Handler):
    def get(self, post_id, comment_id):
        if self.user:
            post = Post.get_by_id(int(post_id), parent=blog_key())
            comment = Comment.get_by_id(
                int(comment_id), parent=self.user.key())
            if comment:
                self.render("newcomment.html", subject=post.subject,
                            content=post.content, comment=comment.comment)
            else:
                self.redirect("/error")
        else:
            self.redirect("/login")

    def post(self, post_id, comment_id):
        if self.user:
            comment = Comment.get_by_id(
                int(comment_id), parent=self.user.key())
            if comment.parent().key().id() == self.user.key().id():
                comment_temp = self.request.get("comment")
                if comment_temp:
                    comment.comment = comment_temp
                    comment.put()
                    self.redirect("/blog/%s" % str(post_id))
                else:
                    error = "Please fill in comment."
                    self.render(
                        "newcomment.html",
                        subject=post.subject,
                        content=post.content,
                        comment=comment.comment)
        else:
            self.redirect("/login")


class DeleteComment(Handler):
    def get(self, post_id, comment_id):
        self.check_restricted_zone()
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment:
            if comment.author == self.check_restricted_zone():
                comment.delete()
                self.redirect("/blog/%s" % str(post_id))
            else:
                self.write("Sorry, something went wrong. Author doesn't match user. %s / %s" % (comment.author, self.check_restricted_zone()))
        else:
            self.write("Sorry, something went wrong. No comment.")


app = webapp2.WSGIApplication(
    [('/blog/signup', SignupPage), ('/blog/welcome', WelcomeHandler), ('/blog/login', LoginPage),
     ('/blog/logout', LogoutPage), ('/blog', MainPage), ('/blog/newpost', NewPostHandler),
     (r'/blog/(\d+)', PostHandler), (r'/blog/edit/(\d+)', PostEditHandler), (r'/blog/delete/(\d+)', PostDeleteHandler),
     (r'/blog/like/(\d+)', PostLikeHandler), ("/blog/([0-9]+)/newcomment", NewComment),
     ("/blog/([0-9]+)/editcomment/([0-9]+)", EditComment),
     ("/blog/([0-9]+)/deletecomment/([0-9]+)", DeleteComment)],
    debug=True)
