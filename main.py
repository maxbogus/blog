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
    """ Main handler with main methods."""

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """ Render template with default params."""
        t = jinja_env.get_template(template)
        params['logged'] = self.read_secure_cookie('user_id')
        params["user"] = self.user
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """ Set cookie with encrypted value."""
        cookie_val = make_secure_val(val)
        value = '%s=%s; Path=/' % (name, cookie_val)
        self.response.headers.add_header('Set-Cookie', value)

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        """ Set id and login cookies."""
        self.set_secure_cookie('user_id', str(user.key().id()))
        self.set_secure_cookie('user_login', str(user.name))

    def logout(self):
        """ Remove values from id and login cookies."""
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.response.headers.add_header('Set-Cookie', 'user_login=; Path=/')

    def initialize(self, *a, **kw):
        """ Initialize request. Read cookie and check user_id in db."""
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and dbmodel.User.by_id(int(uid))


# Authentication section
class SignupPage(Handler):
    """ Signup page handler"""

    def get(self):
        """ Render form"""
        self.render("signup.html")

    def post(self):
        """ Get data from form. By default we assume that we have no error.
        Then we verify data. According to false data we add errors to params
        dict. Then we check if user exist. If not we add it. If exist
        we show error."""
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
    """ Main page handler"""

    def render_front(self, subject='', content='', error=''):
        """ Query to get all posts ordered by created is provided.
        Then page is rendered with query result."""
        query = 'SELECT * FROM Blog ORDER BY created DESC'
        posts = dbmodel.db.GqlQuery(query)
        self.render("blog.html",
                    error=error, subject=subject, content=content, posts=posts)

    def get(self):
        self.render_front()


class WelcomeHandler(Handler):
    """ Welcome page handler"""

    def get(self):
        """ Check auth. If not redirect to signup."""
        if self.user:
            self.render("success.html", username=self.user.name)
        else:
            self.redirect("/blog/signup")


class LoginPage(Handler):
    """ Login page handler"""

    def get(self):
        """ Render page"""
        self.render("login.html")

    def post(self):
        """ Get data from user. Try to get user from db.
        If exist - redirect to welcome. If not - show error."""
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
    """ Logout page handler"""

    def get(self):
        """ Delete user cookies and redirect to signup."""
        self.logout()
        self.redirect("/blog/signup")


class ErrorPageHandler(Handler):
    """ Error page handler"""

    def get(self, error_type):
        """ Error type is got from path.
        Render form."""
        self.render("error.html", error_type=error_type)


class NewPostHandler(Handler):
    """ New post page handler"""

    def get(self):
        """ Auth required for new posts. If not authed - redirect to login."""
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect('/blog/login')

    def post(self):
        """ Auth required for new posts. If not authed - redirect to login.
        Then check fields from user. If data is incomplete - show error."""
        if self.user:
            subject = self.request.get('subject')
            content = self.request.get('content')
            author = self.user.name

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
    """ Post handler"""

    def get(self, post_id):
        """ If there is a post. It is rendered.
        If there is not post - 404 error is shown."""
        post = dbmodel.Blog.get_by_id(int(post_id))

        if not post:
            self.error(404)
            self.render('error.html', error=404)
        else:
            options = self.request.get('options')
            self.render("post.html", post=post, options=options)


class PostEditHandler(Handler):
    """ Post edit handler"""

    def get(self, post_id):
        """ Show edit post form.
        Authorization is required to access form.
        Then we check if post exists. If not 404 error is
        shown to user."""
        if self.user:
            post = dbmodel.Blog.get_by_id(int(post_id))
            subject = post.subject
            content = post.content
            edit = True

            if not post:
                error = 404
                self.error(error)
                self.render('error.html', error=error)
            else:
                self.render("newpost.html",
                            subject=subject,
                            content=content,
                            edit=edit,
                            post=post)
        else:
            self.redirect('/blog/login')

    def post(self, post_id):
        """ Check auth. Show error if auth is incorrect.
        Get subject and content. If any put data in base.
        If not show error."""
        if self.user:
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
        else:
            self.redirect('/blog/login')


class PostDeleteHandler(Handler):
    """ Post delete handler"""

    def get(self, post_id):
        """ Authentication required. Post_id required to open page.
        If post was not found - error page is rendered.
        If post author != current user - error page is rendered."""
        if self.user:
            post = dbmodel.Blog.get_by_id(int(post_id))
            user = self.user.name
            if not post:
                error = "No comment."
                self.render("error.html", error=error)
            elif post.author != user:
                author = post.author
                error = "Author doesn't match user. %s / %s" % (author, user)
                self.render("error.html", error=error)
            else:
                post.delete()
                self.redirect("/blog")
        else:
            self.redirect('/blog/login')


class PostLikeHandler(Handler):
    """ Post like handler"""

    def get(self, post_id):
        """ If user is authorized and his user_name is not
         in list, his like is added to the list.
         If there is not post - he is redirected to error page."""
        if self.user:
            post = dbmodel.Blog.get_by_id(int(post_id))
            if not post:
                error = "No comment."
                self.render("error.html", error=error)
            else:
                author = post.author
                user = self.user.name
                if author == user or user in post.liked_by:
                    self.redirect("/blog/%s" % post_id)
                else:
                    post.liked_by.append(user)
                    post.put()
                    self.redirect("/blog")
        else:
            self.redirect('/blog/login')


class NewComment(Handler):
    """ New comment handler."""

    def get(self, post_id):
        """ To add new comment auth is required. If
        not authorized - send user to login.
        Otherwise render form. Check that post
        exists in data base."""
        if self.user:
            post = dbmodel.Blog.get_by_id(int(post_id))
            if not post:
                error = 404
                self.error(error)
                self.render('error.html', error=error)
            else:
                subject = post.subject
                content = post.content
                self.render("newcomment.html",
                            subject=subject,
                            content=content,
                            pkey=post.key())
        else:
            self.redirect('/blog/login')

    def post(self, post_id):
        """ To add new comment auth is required. If
        not authorized - send user to login.
        Otherwise render form. If post is not existed -
        render error. Check entered data if it's
        incomplete - show error."""
        if self.user:
            post = dbmodel.Blog.get_by_id(int(post_id))
            if not post:
                error = 404
                self.error(error)
                self.render('error.html', error=error)
            else:
                comment = self.request.get("comment")
                author = self.user.name

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
        else:
            self.redirect('/blog/login')


class EditComment(Handler):
    """ Edit comment handler."""

    def get(self, post_id, comment_id):
        """ Show edit post form.
        Authorization is required to access form.
        Then we check if post exists. If not 404 error is
        shown to user."""
        if self.user:
            post = dbmodel.Blog.get_by_id(int(post_id))
            comment = dbmodel.Comment.get_by_id(int(comment_id),
                                                parent=self.user.key())
            edit = True
            if not comment or not post:
                error = 404
                self.error(error)
                self.render('error.html', error=error)
            else:
                self.render("newcomment.html", subject=post.subject,
                            edit=edit,
                            content=post.content, comment=comment.comment,
                            pkey=post.key())
        else:
            self.redirect('/blog/login')

    def post(self, post_id, comment_id):
        """ If user is authorized get user data. Check edits
        and if they exist - add them to base. Otherwise
        ask to add comment."""
        if self.user:
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
        else:
            self.redirect('/blog/login')


class DeleteComment(Handler):
    """ Comment delete handler"""

    def get(self, post_id, comment_id):
        """ Authentication required. Post_id  and
        comment_id are required to open page.
        If post or comment was not found - error page is rendered.
        If post author != current user - error page is rendered."""
        if self.user:
            comment = dbmodel.Comment.get_by_id(int(comment_id),
                                                parent=self.user.key())
            user = self.user.name
            if not comment:
                error = "No comment."
                self.render("error.html", error=error)
            elif comment.author != user:
                author = comment.author
                error = "Author doesn't match user. %s / %s" % (author, user)
                self.render("error.html", error=error)
            else:
                comment.delete()
                self.redirect("/blog/%s" % str(post_id))
        else:
            self.redirect('/blog/login')


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
