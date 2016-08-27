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
import hmac
import os
import re

import jinja2
import webapp2

import dbmodel

# regular expressions to check data entries
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
COOKIE_RE = re.compile(r'.+=;\s*Path=/')

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
loader = jinja2.FileSystemLoader(template_dir)
jinja_env = jinja2.Environment(loader=loader, autoescape=True)


# hash values
def hash_str(s):
    return hmac.new(dbmodel.SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


# functions to validate user data (email, pass, username)
def valid_username(username):
    return USER_RE.match(username)


def valid_password(password):
    return PASSWORD_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)


def valid_cookie(cookie):
    return cookie and COOKIE_RE.match(cookie)


# main handler function
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
        value = '%s=%s; Path=/' % (name, cookie_val)
        self.response.headers.add_header('Set-Cookie', value)

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
        self.user = uid and dbmodel.User.by_id(int(uid))


# Authentication section
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
            u = dbmodel.User.by_name(form_username)
            if u:
                params['username_error'] = 'That user already exists.'
                self.render("signup.html",
                            **params)
            else:
                u = dbmodel.User.register(form_username,
                                          form_password,
                                          form_email)
                u.put()

                self.login(u)
                self.redirect("/blog/welcome")


class MainPage(Handler):
    def render_front(self, subject='', content='', error=''):
        query = 'SELECT * FROM Blog ORDER BY created DESC'
        posts = dbmodel.db.GqlQuery(query)
        self.render("blog.html",
                    error=error, subject=subject, content=content, posts=posts)

    def get(self):
        self.render_front()


class WelcomeHandler(Handler):
    def get(self):
        if self.user:
            self.render("success.html", username=self.user.name)
        else:
            self.redirect("/blog/signup")


class LoginPage(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = dbmodel.User.login(username, password)
        if u:
            self.login(u)
            self.redirect("/blog/welcome")
        else:
            error = 'Invalid login'
            self.render('login.html', error=error)


class LogoutPage(Handler):
    def get(self):
        self.logout()
        self.redirect("/blog/signup")


class ErrorPageHandler(Handler):
    def get(self, error_type):
        self.render("error.html", error_type=error_type)


class NewPostHandler(Handler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect('/blog/login')

    def post(self):
        if self.user:
            subject = self.request.get('subject')
            content = self.request.get('content')
            author = self.request.get("author")

            if subject and content:
                a = dbmodel.Blog(subject=subject,
                                 content=content, author=author, liked_by=[])
                a.put()

                self.redirect("/blog/%s" % a.key().id())
            else:
                error = "Subject and content are required"
                self.render("newpost.html",
                            subject=subject, content=content, error=error)
        else:
            self.redirect('/blog/login')


class PostHandler(Handler):
    def get(self, post_id):
        post = dbmodel.Blog.get_by_id(int(post_id))

        if not post:
            self.error(404)
            self.render('error.html', error=404)
        else:
            options = self.request.get('options')
            self.render("post.html", post=post, options=options)

    def post(self, post_id):
        post = dbmodel.Blog.get_by_id(int(post_id))
        user = dbmodel.User.by_id(self.user)
        self.render("post.html", post=post, user=user)


class PostEditHandler(Handler):
    def get(self, post_id):
        self.check_restricted_zone()
        post = dbmodel.Blog.get_by_id(int(post_id))
        subject = post.subject
        content = post.content
        edit = True

        if not post:
            error = 404
            self.error(error)
            self.render('error.html', error=error)
        else:
            self.render("newpost.html", subject=subject,
                        content=content, edit=edit, post=post)

    def post(self, post_id):
        post = dbmodel.Blog.get_by_id(int(post_id))
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            post.subject = subject
            post.content = content
            post.put()

            self.redirect("/blog/%s" % post.key().id())
        else:
            error = "Subject and content are required"
            self.render("newpost.html",
                        subject=subject, content=content, error=error)


class PostDeleteHandler(Handler):
    def get(self, post_id):
        self.check_restricted_zone()
        self.render("choose.html")

    def post(self, post_id):
        post = dbmodel.Blog.get_by_id(int(post_id))
        opt = self.request.get('optradio')

        if opt == "on":
            post.delete()
            self.redirect("/blog")
        else:
            self.redirect("/blog/delete/%s" % post_id)


class PostLikeHandler(Handler):
    def get(self, post_id):
        self.check_restricted_zone()
        post = dbmodel.Blog.get_by_id(int(post_id))
        author = post.author
        user = self.request.get('author')
        if author == user or user in post.liked_by:
            self.redirect("/blog/%s" % post_id)
        else:
            post.liked_by.append(user)
            post.put()
            self.redirect("/blog")


class NewComment(Handler):
    def get(self, post_id):
        self.check_restricted_zone()
        post = dbmodel.Blog.get_by_id(int(post_id))
        subject = post.subject
        content = post.content
        self.render("newcomment.html",
                    subject=subject,
                    content=content,
                    pkey=post.key())

    def post(self, post_id):
        self.check_restricted_zone()
        post = dbmodel.Blog.get_by_id(int(post_id))
        if not post:
            error = 404
            self.error(error)
            self.render('error.html', error=error)
        else:
            comment = self.request.get("comment")
            author = self.request.get('author')

            if comment:
                c = dbmodel.Comment(comment=comment,
                                    post=post_id,
                                    parent=self.user.key(),
                                    author=author)
                c.put()
                self.redirect("/blog")
            else:
                error = "please comment"
                self.render("post.html",
                            post=post,
                            error=error)


class EditComment(Handler):
    def get(self, post_id, comment_id):
        self.check_restricted_zone()
        post = dbmodel.Blog.get_by_id(int(post_id))
        comment = dbmodel.Comment.get_by_id(int(comment_id),
                                            parent=self.user.key())
        if not comment or not post:
            error = 404
            self.error(error)
            self.render('error.html', error=error)
        else:
            self.render("newcomment.html", subject=post.subject,
                        content=post.content, comment=comment.comment,
                        pkey=post.key())

    def post(self, post_id, comment_id):
        self.check_restricted_zone()
        comment = dbmodel.Comment.get_by_id(int(comment_id),
                                            parent=self.user.key())
        post = dbmodel.Blog.get_by_id(int(post_id))
        comment_edit = self.request.get("comment")
        if comment_edit:
            comment.comment = comment_edit
            comment.put()
            self.redirect("/blog/%s" % str(post_id))
        else:
            error = "Please fill in comment."
            self.render("newcomment.html", subject=post.subject,
                        content=post.content, comment=comment.comment,
                        error=error, pkey=post.key())


class DeleteComment(Handler):
    def get(self, post_id, comment_id):
        self.check_restricted_zone()
        comment = dbmodel.Comment.get_by_id(int(comment_id),
                                            parent=self.user.key())
        if not comment:
            error = "No comment."
            self.write(error)
        elif comment.author != self.check_restricted_zone():
            author = comment.author
            user = self.check_restricted_zone()
            error = "Author doesn't match user. %s / %s" % (author, user)
            self.write(error)
        else:
            comment.delete()
            self.redirect("/blog/%s" % str(post_id))


app = webapp2.WSGIApplication(
    [('/blog/signup', SignupPage),
     ('/blog/welcome', WelcomeHandler),
     ('/blog/login', LoginPage),
     ('/blog/logout', LogoutPage),
     ('/blog', MainPage),
     ('/', MainPage),
     ('/error/(\d+)', ErrorPageHandler),
     ('/blog/newpost', NewPostHandler),
     (r'/blog/(\d+)', PostHandler),
     (r'/blog/edit/(\d+)', PostEditHandler),
     (r'/blog/delete/(\d+)', PostDeleteHandler),
     (r'/blog/like/(\d+)', PostLikeHandler),
     ("/blog/([0-9]+)/newcomment", NewComment),
     ("/blog/([0-9]+)/editcomment/([0-9]+)", EditComment),
     ("/blog/([0-9]+)/deletecomment/([0-9]+)", DeleteComment)],
    debug=True)
