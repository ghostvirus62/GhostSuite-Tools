from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from ghostweb import scan_sql_injection, scan_xss, remote_code_execution, security_misconfiguration, broken_auth, csrf_scan
from subprocess import Popen, PIPE
from flask_bcrypt import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Create tables
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Both username and password are required'}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'error': 'Username already exists'}), 409

    # Hash the password before storing it
    hashed_password = generate_password_hash(password).decode('utf-8')
    
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        # In a real application, you'd generate a secure token here
        token = 'SKYNET'
        return jsonify({'token': token})
    else:
        return jsonify({'error': 'Invalid username or password'}), 401


DEFAULT_ALGORITHM = 'sha256'

@app.route('/ghostencrypter', methods=['POST'])
def encrypt_password():
    data = request.get_json()
    password = data.get('password')
    algorithm = data.get('algorithm', DEFAULT_ALGORITHM)

    try:
        process = Popen(['python', 'ghostencrypter.py', password, algorithm], stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        if stderr:
            return jsonify({'error': stderr.decode('utf-8')}), 400
        else:
            return jsonify({'encrypted_password': stdout.decode('utf-8').strip()}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

DEFAULT_WORDLIST = "directory-list-2.3-medium.txt"

@app.route('/ghostbuster', methods=['POST'])
def scan_directories():
    data = request.get_json()
    url = data.get('url')
    wordlist = data.get('wordlist', DEFAULT_WORDLIST)
    
    # Print for debugging
    print("URL:", url)
    print("Wordlist:", wordlist)

    try:
        # Execute the directory buster script and capture its output
        process = Popen(['python', 'ghostbuster.py', url, '-w', wordlist], stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        # Check for errors
        if stderr:
            return jsonify({'error': stderr.decode('utf-8')}), 400
        else:
            return jsonify({'message': stdout.decode('utf-8').strip()}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    


@app.route('/ghostscan', methods=['POST'])
def scan_ports():
    data = request.get_json()
    target_ip = data.get('target_ip')
    port_range = data.get('port_range')
    num_threads = data.get('num_threads', 1)  # Default to 1 if num_threads is not provided

    try:
        process = Popen(['python', 'ghostscan.py', target_ip, port_range, str(num_threads)], stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        if stderr:
            return jsonify({'error': stderr.decode('utf-8')}), 400
        else:
            return jsonify({'result': stdout.decode('utf-8')}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/ghostweb', methods=['POST'])
def scan_website():
    data = request.get_json()
    url = data.get('url')

    # Execute the vulnerability scanning script
    try:
        process = Popen(['python', 'ghostweb.py', url], stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        if stderr:
            return jsonify({'error': stderr.decode('utf-8')}), 400
        else:
            return jsonify({'result': stdout.decode('utf-8')}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    

if __name__ == '__main__':
    app.run(debug=True)

