import sqlite3
import uuid
import json, random, string
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import hashlib, base64
import bleach
from markupsafe import escape

app = Flask(__name__)
DATABASE = 'market.db'
socketio = SocketIO(app)

# config.json에서 SECRET_KEY 불러오기
try:
    with open('config.json', 'r') as f:
        config = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    config = {'SECRET_KEY': ''}

if not config['SECRET_KEY']:
    config['SECRET_KEY'] = ''.join(random.choice(string.ascii_letters) for _ in range(128))
    with open('config.json', 'w') as f:
        json.dump(config, f, indent=4)
app.config['SECRET_KEY'] = config['SECRET_KEY']

# SHA256 해싱 후 base64 인코딩하여 Fernet 키 생성
def get_fernet_key(secret_key):
    hash_bytes = hashlib.sha256(secret_key.encode()).digest()
    return base64.urlsafe_b64encode(hash_bytes)

fernet = Fernet(get_fernet_key(app.config['SECRET_KEY']))

# HTML Sanitization 허용 태그
def sanitize_html(input_text):
    allowed_tags = ['b', 'i', 'u', 'strong', 'em', 'p', 'br']
    return bleach.clean(input_text, tags=allowed_tags, strip=True)

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                account_number TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        db.commit()

# 데이터베이스 연결
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(_):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.after_request
def set_secure_headers(response):
    response.headers['X-XSS-Protection'] = "1; mode=block"
    response.headers['X-Frame-Options'] = "DENY"
    response.headers['X-Content-Type-Options'] = "nosniff"
    return response

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = escape(request.form['username'])
        raw_password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        hashed_password = generate_password_hash(raw_password)
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_password))
        db.commit()
        flash('회원가입 완료. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = escape(request.form['username'])
        raw_password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user and check_password_hash(user['password'], raw_password):
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        flash('아이디 또는 비밀번호가 올바르지 않습니다.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = sanitize_html(request.form.get('bio', ''))
        encrypted_bio = fernet.encrypt(bio.encode()).decode()
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (encrypted_bio, session['user_id']))
        db.commit()
        flash('프로필 업데이트 완료.')
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    if user and user['bio']:
        try:
            user = dict(user)
            user['bio'] = fernet.decrypt(user['bio'].encode()).decode()
        except Exception:
            user['bio'] = "복호화 오류"
    return render_template('profile.html', user=user)

# 상품 검색 기능
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE title LIKE ?", (f'%{query}%',))
    results = cursor.fetchall()
    return render_template('search.html', query=query, results=results)

# 대시보드: 사용자 정보와 전체 상품 리스트 표시  
# 상품의 description 필드는 복호화하여 보여줌
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()
    decrypted_products = []
    for p in products:
        p = dict(p)
        try:
            p['description'] = fernet.decrypt(p['description'].encode()).decode()
        except Exception:
            p['description'] = "복호화 오류"
        decrypted_products.append(p)
    return render_template('dashboard.html', products=decrypted_products, user=current_user)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = escape(request.form['title'])
        description = sanitize_html(request.form['description'])
        price = escape(request.form['price'])
        account_number = escape(request.form['account_number'])

        if not price.isdigit() or int(price) <= 0:
            flash('가격은 0보다 큰 자연수로 입력해야 합니다.')
            return redirect(url_for('new_product'))

        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        encrypted_description = fernet.encrypt(description.encode()).decode()
        encrypted_account_number = fernet.encrypt(account_number.encode()).decode()
        cursor.execute("INSERT INTO product (id, title, description, price, account_number, seller_id) VALUES (?, ?, ?, ?, ?, ?)",
                       (product_id, title, encrypted_description, price, encrypted_account_number, session['user_id']))
        db.commit()
        flash('상품 등록 완료.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    try:
        product = dict(product)
        product['description'] = fernet.decrypt(product['description'].encode()).decode()
        product['account_number'] = fernet.decrypt(product['account_number'].encode()).decode()
    except Exception:
        product['description'] = "복호화 오류"
        product['account_number'] = "복호화 오류"
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    if request.remote_addr != '127.0.0.1':
        return "Access denied", 403

    db = get_db()
    cursor = db.cursor()

    # 사용자 목록
    cursor.execute("SELECT * FROM user")
    users = cursor.fetchall()

    # 상품 목록
    cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()

    # 신고 목록
    cursor.execute("SELECT * FROM report")
    reports = cursor.fetchall()

    return render_template('admin_dashboard.html', users=users, products=products, reports=reports)

@app.route('/admin/delete_product/<product_id>', methods=['POST'])
def delete_product(product_id):
    if request.remote_addr != '127.0.0.1':
        return "Access denied", 403

    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_report/<report_id>', methods=['POST'])
def delete_report(report_id):
    if request.remote_addr != '127.0.0.1':
        return "Access denied", 403

    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM report WHERE id = ?", (report_id,))
    db.commit()
    flash('신고가 삭제되었습니다.')
    return redirect(url_for('admin_dashboard'))

@socketio.on('send_message')
def handle_send_message_event(data):
    data['message'] = escape(data['message'])
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

if __name__ == '__main__':
    with app.app_context():
        init_db()
    socketio.run(app, debug=False)