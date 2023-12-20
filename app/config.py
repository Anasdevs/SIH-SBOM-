# main.py
from flask import Flask
from app.routes import routes
from dotenv import load_dotenv, dotenv_values
from flask_cors import CORS

app = Flask(__name__)
app.register_blueprint(routes)
CORS(app)

from flask_mail import Mail
import os

load_dotenv()

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_USE_TLS'] = True   # Set it to False if you're using SSL
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")

mail = Mail(app)