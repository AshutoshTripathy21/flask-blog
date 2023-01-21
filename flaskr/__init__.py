import os

from flask import Flask, render_template
from datetime import datetime
from datetime import date
from flask_ckeditor import CKEditor

def create_app(test_config=None):
    from . import auth
    from . import blog

    app = Flask(__name__, instance_relative_config=True)
    #ckeditor = CKEditor(app)
    
    ckeditor = CKEditor(app)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
    )

    if test_config is None:
        app.config.from_pyfile('config.py', silent=True)
    else:
        app.config.from_mapping(test_config)

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
    from . import db
    db.init_app(app)

    app.register_blueprint(auth.bp)

    app.register_blueprint(blog.bp)
    app.add_url_rule('/', endpoint='index')

    #create search function

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404

    #internal server error
    @app.errorhandler(500)
    def page_not_found(e):
        return render_template('500.html'), 500
    
    @app.route('/date')
    def get_current_date():
        return {"Date": date.today()}

    return app