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
import os

import jinja2
import webapp2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)


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
        self.render("post.html", post=post)

app = webapp2.WSGIApplication([('/blog', MainPage), ('/blog/newpost', NewPostHandler), (r'/blog/(\d+)', PostHandler)],
                              debug=True)
