# app.py
from flask import Flask, render_template, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, current_user
from datetime import datetime
import paramiko
import pandas as pd
import os
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler
import json
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sftp_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configure logging
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/sftp_manager.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('SFTP Manager startup')

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    host = db.Column(db.String(128), nullable=False)
    port = db.Column(db.Integer, nullable=False, default=22)
    username = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    remote_path = db.Column(db.String(256))
    server_type = db.Column(db.String(16))  # 'download' or 'upload'
    store_ids = db.Column(db.String(512))  # JSON string of store IDs
    is_default = db.Column(db.Boolean, default=False)

# SFTP Operations Class
class SFTPOperations:
    def __init__(self, server):
        self.server = server
        self.transport = None
        self.sftp = None

    def connect(self):
        try:
            self.transport = paramiko.Transport((self.server.host, self.server.port))
            self.transport.connect(username=self.server.username, password=self.server.password)
            self.sftp = paramiko.SFTPClient.from_transport(self.transport)
            return True
        except Exception as e:
            app.logger.error(f"Connection failed to {self.server.name}: {str(e)}")
            return False

    def disconnect(self):
        if self.sftp:
            self.sftp.close()
        if self.transport:
            self.transport.close()

    def download_files(self, local_path, file_pattern=None):
        if not self.connect():
            return []

        try:
            self.sftp.chdir(self.server.remote_path)
            remote_files = self.sftp.listdir()
            downloaded_files = []

            for remote_file in remote_files:
                if file_pattern and not remote_file.startswith(file_pattern):
                    continue

                local_file_path = os.path.join(local_path, remote_file)
                self.sftp.get(remote_file, local_file_path)
                downloaded_files.append(local_file_path)
                app.logger.info(f"Downloaded: {remote_file}")

            return downloaded_files
        except Exception as e:
            app.logger.error(f"Download error: {str(e)}")
            return []
        finally:
            self.disconnect()

    def upload_file(self, local_file, remote_path):
        if not self.connect():
            return False

        try:
            self.sftp.put(local_file, remote_path)
            app.logger.info(f"Uploaded: {local_file} to {remote_path}")
            return True
        except Exception as e:
            app.logger.error(f"Upload error: {str(e)}")
            return False
        finally:
            self.disconnect()

# Routes
@app.route('/')
@login_required
def index():
    servers = Server.query.all()
    return render_template('index.html', servers=servers)

@app.route('/server/add', methods=['GET', 'POST'])
@login_required
def add_server():
    if request.method == 'POST':
        server = Server(
            name=request.form['name'],
            host=request.form['host'],
            port=int(request.form['port']),
            username=request.form['username'],
            password=request.form['password'],
            remote_path=request.form['remote_path'],
            server_type=request.form['server_type'],
            store_ids=json.dumps(request.form['store_ids'].split(','))
        )
        db.session.add(server)
        db.session.commit()
        flash('Server added successfully')
        return redirect(url_for('index'))
    return render_template('server_form.html')

@app.route('/server/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_server(id):
    server = Server.query.get_or_404(id)
    if request.method == 'POST':
        server.name = request.form['name']
        server.host = request.form['host']
        server.port = int(request.form['port'])
        server.username = request.form['username']
        server.password = request.form['password']
        server.remote_path = request.form['remote_path']
        server.store_ids = json.dumps(request.form['store_ids'].split(','))
        db.session.commit()
        flash('Server updated successfully')
        return redirect(url_for('index'))
    return render_template('server_form.html', server=server)

@app.route('/process', methods=['POST'])
@login_required
def process_files():
    download_server = Server.query.filter_by(server_type='download', is_default=True).first()
    upload_server = Server.query.filter_by(server_type='upload', is_default=True).first()
    
    if not download_server or not upload_server:
        flash('Default servers not configured')
        return redirect(url_for('index'))

    # Create temporary directory for processing
    temp_dir = os.path.join(app.root_path, 'temp')
    os.makedirs(temp_dir, exist_ok=True)

    # Download files
    sftp_download = SFTPOperations(download_server)
    downloaded_files = sftp_download.download_files(temp_dir)

    if not downloaded_files:
        flash('No files downloaded')
        return redirect(url_for('index'))

    # Process files
    store_ids = json.loads(download_server.store_ids)
    combined_df = pd.DataFrame()

    for file in downloaded_files:
        df = pd.read_csv(file)
        filtered_df = df[df['store_id'].isin(store_ids)]
        combined_df = pd.concat([combined_df, filtered_df], ignore_index=True)

    # Save processed file
    date_today = datetime.now().strftime('%d%m%y')
    output_file = os.path.join(temp_dir, f'processed_data_{date_today}.xlsx')
    combined_df.to_excel(output_file, index=False)

    # Upload processed file
    sftp_upload = SFTPOperations(upload_server)
    remote_path = f"{upload_server.remote_path}/processed_data_{date_today}.xlsx"
    
    if sftp_upload.upload_file(output_file, remote_path):
        flash('Files processed and uploaded successfully')
    else:
        flash('Error during upload')

    # Cleanup
    for file in downloaded_files:
        os.remove(file)
    os.remove(output_file)

    return redirect(url_for('index'))

@app.route('/logs')
@login_required
def view_logs():
    with open('logs/sftp_manager.log', 'r') as f:
        logs = f.readlines()
    return render_template('logs.html', logs=logs)

# Create database tables
with app.app_context():
    db.create_all()
    
    # Create default servers if they don't exist
    if not Server.query.filter_by(name='Glovo').first():
        glovo_server = Server(
            name='Glovo',
            host='sftp-partners.glovoapp.com',
            port=22,
            username='carrefour-ma',
            password='l7ArAHotIzDu6U2uYisRGrUt',
            remote_path='/glovoapp-partners-sftp-bucket-121e9009/home/carrefour-ma/input_carrefour-ma',
            server_type='download',
            store_ids=json.dumps([195, 166, 106, 746, 177, 741, 744, 187, 657, 652, 135]),
            is_default=True
        )
        db.session.add(glovo_server)

    if not Server.query.filter_by(name='Ora').first():
        ora_server = Server(
            name='Ora',
            host='ftp-carrefour.ora.ma',
            port=22,
            username='ora-ftp',
            password='gEEw9KeK5^9D^ZWK',
            remote_path='/public_ftp',
            server_type='upload',
            is_default=True
        )
        db.session.add(ora_server)

    db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)