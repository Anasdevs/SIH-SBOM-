# main.py
from flask import Flask
from app.routes import routes

app = Flask(__name__)
app.register_blueprint(routes)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
