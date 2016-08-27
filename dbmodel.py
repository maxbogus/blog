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
import random
import string

from google.appengine.ext import db

# secret word
SECRET = 'fghjfhgl6lk5jl4k5jglf9559'


# hash data in data base
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


class User(db.Model):
    """ User table. Name and pw_hash are required properties."""
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        """ Method to get user by id."""
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        """ Method to get user by name."""
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        """ Register new user with hashed pw."""
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name, pw_hash=pw_hash, email=email)

    @classmethod
    def login(cls, name, pw):
        """ Get user by name and validate its properties.
        Returns user object."""
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Blog(db.Model):
    """ Blog table. Subject and content, are used in post.
    Author is required for edit rights checking.
    Created used in sorting. Liked_by is required for like functionality."""
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    liked_by = db.ListProperty(str)

    @property
    def comments(self):
        """ This property is required to associate comments with blog."""
        return Comment.all().filter("post = ", str(self.key().id()))


class Comment(db.Model):
    """ Comment table. All columns are required """
    comment = db.TextProperty(required=True)
    post = db.StringProperty(required=True)
    author = db.StringProperty(required=True)


def users_key(group='default'):
    return db.Key.from_path('users', group)
