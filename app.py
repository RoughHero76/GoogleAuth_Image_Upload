from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session, jsonify
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_oauthlib.client import OAuth
from dotenv import load_dotenv
import os
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)

secret_key = os.urandom(24) 
app.secret_key = secret_key
oauth = OAuth(app)
oauth.init_app(app)


app.config['UPLOAD_FOLDER'] = os.path.join('uploads')
load_dotenv()

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per minute"]
)

CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
google = oauth.register(
    name='google',
    server_metadata_url=CONF_URL,
    client_id= os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET"),
    client_kwargs={
        'scope': 'openid email profile'
    },
)

@app.route('/')
@limiter.limit("5/minute")
def upload_form():
    if 'token' in session:
        # Get a list of uploaded image filenames
        upload_folder = app.config['UPLOAD_FOLDER']
        uploaded_images = os.listdir(upload_folder)

        return render_template('upload.html', uploaded_images=uploaded_images)
    else:
        return render_template('login.html')

@app.route('/google-login')
def googleLogin():
    redirect_uri = url_for('authorize', _external=True)
    google = oauth.create_client('google')
    return google.authorize_redirect(redirect_uri)

@app.route('/logout')
def logout():
    session.pop('token', None)
    return redirect(url_for('upload_form'))

@app.route('/delete_image/<filename>', methods=['GET', 'POST'])
def delete_image(filename):
    if 'token' in session:
        upload_folder = app.config['UPLOAD_FOLDER']
        file_path = os.path.join(upload_folder, filename)

        if os.path.exists(file_path):
            os.remove(file_path)

        return redirect(url_for('upload_form'))
    else:
        return 'You are not logged in'

@app.route('/authorize')
def authorize():
    token = oauth.google.authorize_access_token()
    session['token'] = (token['access_token'], '')
    user = token['userinfo']
    return redirect('/')

@app.route('/upload', methods=['POST'])
def upload_image():
    if 'file' not in request.files:
        return redirect(request.url)

    file = request.files['file']

    if file.filename == '':
        return redirect(request.url)
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return redirect(url_for('display_image', filename=filename))

@app.route('/display/<filename>')
def display_image(filename):
    if 'token' in session:
        return render_template('image_display.html', filename=filename)
    else:
        return 'You are not logged In'

@app.route('/static/uploads/<path:filename>')
def serve_static(filename):
    if 'token' in session:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    else:
        return 'You are not logged In'

if __name__ == '__main__':
    #app.run(debug=True)
    app.run(debug=False, port=5000, host='0.0.0.0')
