#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
"""
    LLXC
"""
from __future__ import with_statement
from sqlite3 import dbapi2 as sqlite3
from contextlib import closing
from flask import Flask, request, session, g, redirect, url_for, \
     render_template, flash
import subprocess

# configuration
DATABASE = 'llxc.db'
DEBUG = True
SECRET_KEY = 'development key'
USERNAME = 'admin'
PASSWORD = 'default'

# create our little application :)
app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('LLXC_SETTINGS', silent=True)


def connect_db():
    """Returns a new connection to the database."""
    return sqlite3.connect(app.config['DATABASE'])


def init_db():
    """Creates the database tables."""
    with closing(connect_db()) as db:
        with app.open_resource('schema.sql') as f:
            db.cursor().executescript(f.read())
        db.commit()


@app.before_request
def before_request():
    """Make sure we are connected to the database each request."""
    g.db = connect_db()


@app.teardown_request
def teardown_request(exception):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'db'):
        g.db.close()


@app.route('/')
def show_entries():
    """Show server status"""
    uptime = subprocess.check_output(["uptime"], shell=True)
    hostname = subprocess.check_output(["hostname"], shell=True)
    diskusage = subprocess.check_output(["df -h |"
                                         "grep rootfs | awk '{print $5}'"],
                                         shell=True)
    return render_template('home.html', uptime=uptime, diskusage=diskusage,
                           hostname=hostname)


@app.route('/list')
def list():
    """Show a list of containers"""
    import subprocess
    entries = "Not Implemented"
    print entries
    return render_template('list.html', entries=entries)


@app.route('/container/<containername>')
def show_container(container):
    """Show container details"""
    #Container stuff
    return 'Container %s' % containername


@app.route('/create', methods=['GET', 'POST'])
def create():
    """Create a container"""
    return render_template('create.html')


@app.route('/admin')
def admin():
    """Administer an LLXC System"""
    sshpubkey = subprocess.check_output(["cat ~/.ssh/id_rsa.pub"], shell=True)
    return render_template('admin.html', sshpubkey=sshpubkey)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Log a user in to the system"""
    error = None
    if request.method == 'POST':
        if request.form['username'] != app.config['USERNAME']:
            error = 'Invalid username'
        elif request.form['password'] != app.config['PASSWORD']:
            error = 'Invalid password'
        else:
            session['logged_in'] = True
            flash('You are now logged in')
            return redirect(url_for('list'))
    return render_template('login.html', error=error)


@app.errorhandler(404)
def page_not_found(error):
    """Return a 404 Page"""
    flash('Error 404: Page could not be found, here\'s the homepage instead.')
    return render_template('home.html'), 404


@app.route('/logout')
def logout():
    """Log a user out"""
    session.pop('logged_in', None)
    flash('You are now logged out')
    return redirect(url_for('show_entries'))


if __name__ == '__main__':
    app.run(host='0.0.0.0')
