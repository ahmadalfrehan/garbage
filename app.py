import pyclamd
from flask import Flask, jsonify, request, send_from_directory, session, render_template_string,redirect
from flask_sqlalchemy import SQLAlchemy
# from flask import escape
from markupsafe import escape
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_uploads import UploadSet, configure_uploads, DOCUMENTS
import os
from cryptography import x509
from CA import verify_signature
from cryptography.hazmat.primitives import serialization, hashes


from CA import sign_document
import os
from flask import send_from_directory
import clamd
import html
import secrets

# Initialize Flask App
app = Flask(__name__)

app.secret_key =secrets.token_hex(32) #"a_unique_secure_key_1234567890"
print(secrets.token_hex(32))
# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_secret_key'
app.config['UPLOADED_DOCUMENTS_DEST'] = 'uploads/documents'

documents = UploadSet('documents', DOCUMENTS)
app.config['UPLOADED_DOCUMENTS_ALLOW'] = {'pdf'}
configure_uploads(app, documents)

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
cors = CORS(app)
documents = UploadSet('documents', DOCUMENTS)
configure_uploads(app, documents)

# Ensure upload directory exists
os.makedirs(app.config['UPLOADED_DOCUMENTS_DEST'], exist_ok=True)

# CSP:Implemented using @after_request to add a Content-Security-Policy header to every response.
# Add Content Security Policy headers (CSP)
# default-src 'self': Restricts all resources (scripts, styles, etc.) to the same origin
# script-src 'self': Allows execution of scripts only from the same origin


@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self'; "
        "font-src 'self'; "
    )
    return response

# Models


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    national_id = db.Column(db.String(50), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    password = db.Column(db.String(200), nullable=False)


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_name = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(200), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=db.func.current_timestamp())


# Hardcoded admin credentials (better to use environment variables)
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')  # Default: 'admin'
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')  # Default: 'admin123'


# Create the database
with app.app_context():
    db.create_all()


@app.route('/verify', methods=['POST'])
def verify_file_signature():
    data = request.form
    file_path = data.get('file_path')
    signature_path = data.get('signature_path')

    if not file_path or not signature_path:
        return jsonify(message="File path and signature path are required"), 400

    with open("ca_certificate.pem", "rb") as cert_file:
        ca_cert = x509.load_pem_x509_certificate(cert_file.read())
        public_key = ca_cert.public_key()

    try:
        verify_signature(file_path, signature_path, public_key)
        return jsonify(message="Signature is valid"), 200
    except Exception as e:
        return jsonify(message=f"Signature verification failed: {str(e)}"), 400


@app.route('/sign', methods=['POST'])
def sign_file():
    if 'file' not in request.files:
        return jsonify(message="No file uploaded"), 400

    file = request.files['file']
    file_path = os.path.join('uploads', file.filename)
    file.save(file_path)

    # Load the CA's private key
    with open("ca_private_key.pem", "rb") as key_file:
        ca_key = serialization.load_pem_private_key(
            key_file.read(), password=None)

    # Sign the file
    try:
        sign_document(file_path, ca_key)
        return jsonify(message="File signed successfully", signature=f"{file_path}.sig"), 200
    except Exception as e:
        return jsonify(message=f"Error signing file: {str(e)}"), 500


# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(
        data['password']).decode('utf-8')

    # Check if the national ID already exists
    existing_user = User.query.filter_by(
        national_id=data['national_id']).first()
    if existing_user:
        return jsonify(message="National ID already registered"), 400

    new_user = User(
        name=data['name'],
        national_id=data['national_id'],
        phone=data['phone'],
        password=hashed_password
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify(message="User registered successfully"), 201

# User Login


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(national_id=data['national_id']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        # Create access token
        access_token = create_access_token(
            identity={'id': user.id, 'national_id': user.national_id})
        return jsonify(access_token=access_token), 200
    return jsonify(message="Invalid credentials"), 401

# Upload Document


@app.route('/submit', methods=['POST'])
def submit():
  # Get user input from the request
    user_input = request.form.get('user_input', '')

    # Encode the input to prevent XSS
    safe_input = html.escape(user_input)

    # Return the sanitized input
    return jsonify({"message": "Input processed successfully", "safe_input": safe_input})


def initialize_clamav():
    try:
        clam = pyclamd.ClamdUnixSocket()  # For Unix systems
        if not clam.ping():
            raise Exception("ClamAV daemon not running")
        return clam
    except:
        try:
            clam = pyclamd.ClamdNetworkSocket(
                host='127.0.0.1', port=3310)  # For network-based ClamAV
            if not clam.ping():
                raise Exception("ClamAV daemon not reachable")
            return clam
        except Exception as e:
            print(f"Error initializing ClamAV: {e}")
            return None


clamav = initialize_clamav()


@app.route('/upload', methods=['POST'])
@jwt_required()
def upload():
    current_user = get_jwt_identity()
    user_id = current_user['id']

    if 'file' not in request.files:
        return jsonify(message="No file uploaded"), 400

    file = request.files['file']
    file_path = os.path.join(
        app.config['UPLOADED_DOCUMENTS_DEST'], file.filename)

    file.save(file_path)

    if clamav:
        try:
            scan_result = clamav.scan_file(file_path)  # Scan the file
            if scan_result:
                os.remove(file_path)  # Delete infected file
                return jsonify(message="File contains a virus and was rejected"), 400
        except Exception as e:
            return jsonify(message=f"Error scanning file: {str(e)}"), 500

    # return jsonify(message="File uploaded successfully"), 200

    new_document = Document(
        owner_id=user_id,
        file_name=file.filename,
        file_path=file_path
    )
    db.session.add(new_document)
    db.session.commit()

    return jsonify(message="Document uploaded successfully"), 201


def admin_required(func):
    def wrapper(*args, **kwargs):
        if not session.get('admin_authenticated'):
            return jsonify(message="Access denied"), 403
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__  # Avoid Flask route naming conflicts
    return wrapper


# Download Document
@app.route('/download/<int:doc_id>', methods=['GET'])
@admin_required
def download(doc_id):
    # current_user = get_jwt_identity()
    document = Document.query.get(doc_id)
    if True:#document and document.owner_id == current_user['id']:
        return send_from_directory('uploads/documents', document.file_name)
    return jsonify(message="Document not found or access denied"), 404


# Hardcoded admin credentials
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')

# Admin login route


@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session['admin_authenticated'] = True
        return jsonify(message="Admin login successful"), 200
    else:
        return jsonify(message="Invalid credentials"), 401

# Admin logout route


@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    session.pop('admin_authenticated', None)
    return jsonify(message="Admin logged out"), 200




@app.route('/admin/search', methods=['GET'])
def admin_search():
    # Ensure the user is authenticated as an admin
    if not session.get("admin_authenticated"):
        return jsonify(message="Access denied"), 403

    # Get the national_id from query parameters
    national_id = request.args.get("national_id")
    if not national_id:
        return jsonify(message="National ID is required"), 400

    # Query the database to find the user by national_id
    user = User.query.filter_by(national_id=national_id).first()
    if not user:
        return jsonify(message="No user found with this National ID"), 404

    # Query documents owned by this user
    documents = Document.query.filter_by(owner_id=user.id).all()

    # Convert documents to a list of dictionaries
    document_list = [
        {
            "id": doc.id,
            "owner_id": doc.owner_id,
            "file_name": doc.file_name,
            "file_path": doc.file_path,
            "uploaded_at": doc.uploaded_at.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for doc in documents
    ]

    return jsonify(results=document_list), 200




# @app.route('/admin/search', methods=['GET'])
# # @jwt_required()
# def admin_search():
#     # Example of admin search route
#     documents = Document.query.all()
#     results = [
#         {
#             'id': doc.id,
#             'owner_id': doc.owner_id,
#             'file_name': doc.file_name,
#             'uploaded_at': doc.uploaded_at
#         } for doc in documents
#     ]
#     return jsonify(results=results), 200




@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory('frontend', filename)


@app.route('/user')
def serve_user_index():
    return send_from_directory('frontend/user', 'index.html')


@app.route('/admin')
# @admin_required
def serve_admin_index():
    return send_from_directory('frontend/admin', 'index.html')


# @app.route('/admin/login', methods=["GET", "POST"])
# def serve_admin_login():
#     # Check if admin is already authenticated
#     if request.method == "POST":
#         data = request.form
#         username = data.get("username")
#         password = data.get("password")

#         if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
#             session["admin_authenticated"] = True
#             return redirect("/admin")
#         else:
#             return jsonify(message="Invalid credentials"), 401

#     # Serve the login form
#     login_page = """
#     <!DOCTYPE html>
#     <html lang="en">
#     <head>
#         <meta charset="UTF-8">
#         <meta name="viewport" content="width=device-width, initial-scale=1.0">
#         <title>Admin Login</title>
#         <style>
#             body {
#                 font-family: Arial, sans-serif;
#                 background-color: #f8f9fa;
#                 margin: 0;
#                 padding: 0;
#                 display: flex;
#                 justify-content: center;
#                 align-items: center;
#                 height: 100vh;
#             }
#             .login-container {
#                 width: 300px;
#                 padding: 20px;
#                 background: white;
#                 box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
#                 border-radius: 8px;
#             }
#             .login-container h2 {
#                 margin-bottom: 20px;
#                 text-align: center;
#             }
#             .login-container label {
#                 display: block;
#                 margin-bottom: 8px;
#                 font-size: 14px;
#             }
#             .login-container input {
#                 width: 100%;
#                 padding: 10px;
#                 margin-bottom: 20px;
#                 border: 1px solid #ccc;
#                 border-radius: 4px;
#             }
#             .login-container button {
#                 width: 100%;
#                 padding: 10px;
#                 background-color: #007bff;
#                 color: white;
#                 border: none;
#                 border-radius: 4px;
#                 cursor: pointer;
#             }
#             .login-container button:hover {
#                 background-color: #0056b3;
#             }
#         </style>
#     </head>
#     <body>
#         <div class="login-container">
#             <h2>Admin Login</h2>
#             <form id="admin-login-form" method="POST">
#                 <label for="username">Username</label>
#                 <input type="text" id="username" name="username" required>
#                 <label for="password">Password</label>
#                 <input type="password" id="password" name="password" required>
#                 <button type="submit">Login</button>
#             </form>
#         </div>
#         <script>
#             const form = document.getElementById("admin-login-form");
#             form.addEventListener("submit", async (event) => {
#                 event.preventDefault();
#                 const formData = new FormData(form);
#                 const response = await fetch("/admin", {
#                     method: "POST",
#                     body: formData,
#                 });
#                 const data = await response.json();
#                 if (response.ok) {
#                     alert(data.message);
#                     // Redirect to admin panel (replace with your admin panel URL)
#                     window.location.href = "/admin/panel";
#                 } else {
#                     alert(data.message);
#                 }
#             });
#         </script>
#     </body>
#     </html>
#     """
#     return render_template_string(login_page)


# Run Server
if __name__ == '__main__':
    # app.run(debug=True)
    app.run(ssl_context=("server_certificate.pem", "server_private_key.pem"),debug=False)
