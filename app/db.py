import sqlite3
from . import dbc
from sqlite3 import Error
import click
from flask import current_app, g
from flask.cli import with_appcontext

def get_db():
    try:
        if 'db' not in g:
            print(current_app.config['DATABASE'])
            g.db = sqlite3.connect(current_app.config['DATABASE'])
        return g.db
    except Error:
        print(Error)
    


def close_db(e=None):
    db = g.pop('db', None)

    if db is not None:
        print('conexion cerrada')
        db.close()


def init_db():
    db = get_db()

    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))
 
    
@click.command('init-db')
@with_appcontext
def init_db_command():
    """Clear the existing data and create new tables."""
    init_db()
    click.echo('Initialized the database.')


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)