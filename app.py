# app.py - 主應用文件
import os
import sqlite3
import secrets
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['DATABASE'] = os.path.join(app.instance_path, 'messages.db')
app.config['UPLOAD_FOLDER'] = os.path.join(app.static_folder, 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# 確保uploads目錄存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# 確保instance目錄存在
os.makedirs(app.instance_path, exist_ok=True)

# 添加 reCAPTCHA 配置
app.config['RECAPTCHA_SITE_KEY'] = ''  # 從 Google reCAPTCHA 獲取
app.config['RECAPTCHA_SECRET_KEY'] = ''  # 從 Google reCAPTCHA 獲取

# 檢查允許的文件擴展名
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# 驗證 reCAPTCHA 的函數
def verify_recaptcha():
    recaptcha_response = request.form.get('g-recaptcha-response')
    if not recaptcha_response:
        return False
    
    # 發送驗證請求到 Google
    payload = {
        'secret': app.config['RECAPTCHA_SECRET_KEY'],
        'response': recaptcha_response,
        'remoteip': request.remote_addr
    }
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    result = response.json()
    
    return result.get('success', False)
    
def get_db():
    db = sqlite3.connect(app.config['DATABASE'], timeout=20)  # 添加超時參數
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin BOOLEAN NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        nickname TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        is_private BOOLEAN NOT NULL DEFAULT 0,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );

    -- 創建文章表格
    CREATE TABLE IF NOT EXISTS blog_posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );

    -- 創建用戶資料表格
    CREATE TABLE IF NOT EXISTS user_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        background_image TEXT,
        bio TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );

    -- 創建索引以提高查詢性能
    CREATE INDEX IF NOT EXISTS idx_messages_user_id ON messages(user_id);
    CREATE INDEX IF NOT EXISTS idx_blog_posts_user_id ON blog_posts(user_id);
    ''')
    db.commit()

# 創建管理員帳戶
def create_admin(username, password):
    """創建管理員帳戶"""
    try:
        db = get_db()
        hashed_password = generate_password_hash(password)
        db.execute(
            'INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
            (username, hashed_password, True)
        )
        db.commit()
        return True
    except sqlite3.IntegrityError:
        # 可能用戶名已存在
        return False
    except sqlite3.OperationalError as e:
        # 處理數據庫鎖定問題
        print(f"數據庫操作錯誤: {e}")
        db.rollback()  # 回滾任何未完成的事務
        return False
    finally:
        db.close()  # 確保關閉連接

# 路由設置
@app.route('/')
def index():
    db = get_db()
    messages = db.execute(
        'SELECT m.id, m.content, m.nickname, m.created_at, m.is_private, u.username '
        'FROM messages m JOIN users u ON m.user_id = u.id '
        'WHERE m.is_private = 0 OR (m.is_private = 1 AND ? = 1) '
        'ORDER BY m.created_at DESC',
        (session.get('is_admin', 0),)
    ).fetchall()
    
    # 獲取最新的3篇博客文章
    blog_posts = db.execute(
        'SELECT p.id, p.title, substr(p.content, 1, 200) as preview, p.created_at, u.username '
        'FROM blog_posts p JOIN users u ON p.user_id = u.id '
        'ORDER BY p.created_at DESC LIMIT 3'
    ).fetchall()
    
    return render_template('index.html', 
                           messages=messages, 
                           blog_posts=blog_posts, 
                           is_admin=session.get('is_admin', False))

@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = '錯誤的用戶名'
        elif not check_password_hash(user['password'], password):
            error = '錯誤的密碼'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            
            # 檢查用戶是否有個人資料，如果沒有則創建
            profile = db.execute(
                'SELECT * FROM user_profiles WHERE user_id = ?', (user['id'],)
            ).fetchone()
            
            if profile is None:
                db.execute(
                    'INSERT INTO user_profiles (user_id, background_image, bio) VALUES (?, ?, ?)',
                    (user['id'], 'default_bg.jpg', '歡迎來到我的頁面！')
                )
                db.commit()
                
            return redirect(url_for('index'))

        flash(error)

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/message', methods=('GET', 'POST'))
def create_message():
    if request.method == 'POST':
        content = request.form['content']
        nickname = request.form['nickname']
        is_private = 'is_private' in request.form
        user_id = session.get('user_id', 1)  # 默認使用訪客帳戶
        
        if not content:
            flash('留言內容不能為空')
            return redirect(url_for('create_message'))
        
        if not nickname:
            nickname = "匿名" if user_id == 1 else session.get('username', '用戶')
        
        # 驗證 reCAPTCHA
        if not verify_recaptcha():
            flash('請完成人機驗證')
            return redirect(url_for('create_message'))
        
        db = get_db()
        db.execute(
            'INSERT INTO messages (content, nickname, is_private, user_id) VALUES (?, ?, ?, ?)',
            (content, nickname, is_private, user_id)
        )
        db.commit()
        flash('留言發送成功!')
        return redirect(url_for('index'))
    
    return render_template('create_message.html')

@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = False
        
        db = get_db()
        error = None

        if not username:
            error = '請輸入用戶名'
        elif not password:
            error = '請輸入密碼'
        elif db.execute(
            'SELECT id FROM users WHERE username = ?', (username,)
        ).fetchone() is not None:
            error = f'用戶 {username} 已經存在'

        if error is None:
            # 創建用戶
            db.execute(
                'INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                (username, generate_password_hash(password), is_admin)
            )
            db.commit()
            
            # 獲取新創建的用戶ID
            user = db.execute(
                'SELECT id FROM users WHERE username = ?', (username,)
            ).fetchone()
            
            # 創建用戶資料
            db.execute(
                'INSERT INTO user_profiles (user_id, background_image, bio) VALUES (?, ?, ?)',
                (user['id'], 'default_bg.jpg', '歡迎來到我的頁面！')
            )
            db.commit()
            
            flash('註冊成功，請登入')
            return redirect(url_for('login'))

        flash(error)

    return render_template('register.html')

@app.route('/delete/<int:id>', methods=('POST',))
def delete_message(id):
    if not session.get('is_admin', False):
        abort(403)
    
    db = get_db()
    db.execute('DELETE FROM messages WHERE id = ?', (id,))
    db.commit()
    flash('留言已刪除')
    return redirect(url_for('index'))

# 新增博客相關路由
@app.route('/blog')
def blog_list():
    db = get_db()
    blog_posts = db.execute(
        'SELECT p.id, p.title, substr(p.content, 1, 200) as preview, '
        'p.created_at, p.user_id, u.username '
        'FROM blog_posts p JOIN users u ON p.user_id = u.id '
        'ORDER BY p.created_at DESC'
    ).fetchall()
    
    return render_template('blog_list.html', blog_posts=blog_posts)

@app.route('/blog/<int:id>')
def blog_detail(id):
    db = get_db()
    post = db.execute(
        'SELECT p.id, p.title, p.content, p.created_at, p.updated_at, '
        'p.user_id, u.username '
        'FROM blog_posts p JOIN users u ON p.user_id = u.id '
        'WHERE p.id = ?',
        (id,)
    ).fetchone()
    
    if post is None:
        abort(404)
    
    # 獲取作者的背景圖片
    profile = db.execute(
        'SELECT background_image FROM user_profiles WHERE user_id = ?',
        (post['user_id'],)
    ).fetchone()
    
    background_image = profile['background_image'] if profile else 'default_bg.jpg'
    
    return render_template('blog_detail.html', post=post, background_image=background_image)

@app.route('/blog/create', methods=('GET', 'POST'))
def blog_create():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        user_id = session.get('user_id')
        
        if not title:
            flash('文章標題不能為空')
            return redirect(url_for('blog_create'))
        
        if not content:
            flash('文章內容不能為空')
            return redirect(url_for('blog_create'))
        
        db = get_db()
        db.execute(
            'INSERT INTO blog_posts (title, content, user_id) VALUES (?, ?, ?)',
            (title, content, user_id)
        )
        db.commit()
        flash('文章發佈成功!')
        return redirect(url_for('blog_list'))
    
    return render_template('blog_create.html')

@app.route('/blog/edit/<int:id>', methods=('GET', 'POST'))
def blog_edit(id):
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    db = get_db()
    post = db.execute(
        'SELECT * FROM blog_posts WHERE id = ?', (id,)
    ).fetchone()
    
    if post is None:
        abort(404)
    
    # 檢查是否為作者或管理員
    if post['user_id'] != session.get('user_id') and not session.get('is_admin', False):
        abort(403)
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        if not title:
            flash('文章標題不能為空')
            return redirect(url_for('blog_edit', id=id))
        
        if not content:
            flash('文章內容不能為空')
            return redirect(url_for('blog_edit', id=id))
        
        db.execute(
            'UPDATE blog_posts SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP '
            'WHERE id = ?',
            (title, content, id)
        )
        db.commit()
        flash('文章更新成功!')
        return redirect(url_for('blog_detail', id=id))
    
    return render_template('blog_edit.html', post=post)

@app.route('/blog/delete/<int:id>', methods=('POST',))
def blog_delete(id):
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    db = get_db()
    post = db.execute(
        'SELECT * FROM blog_posts WHERE id = ?', (id,)
    ).fetchone()
    
    if post is None:
        abort(404)
    
    # 檢查是否為作者或管理員
    if post['user_id'] != session.get('user_id') and not session.get('is_admin', False):
        abort(403)
    
    db.execute('DELETE FROM blog_posts WHERE id = ?', (id,))
    db.commit()
    flash('文章已刪除')
    return redirect(url_for('blog_list'))

# 用戶資料相關路由
@app.route('/profile', methods=('GET', 'POST'))
def profile():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    db = get_db()
    user_id = session.get('user_id')
    
    # 獲取用戶資料
    profile = db.execute(
        'SELECT * FROM user_profiles WHERE user_id = ?', (user_id,)
    ).fetchone()
    
    if profile is None:
        # 如果沒有資料，創建一個新的
        db.execute(
            'INSERT INTO user_profiles (user_id, background_image, bio) VALUES (?, ?, ?)',
            (user_id, 'default_bg.jpg', '歡迎來到我的頁面！')
        )
        db.commit()
        profile = db.execute(
            'SELECT * FROM user_profiles WHERE user_id = ?', (user_id,)
        ).fetchone()
    
    if request.method == 'POST':
        bio = request.form['bio']
        
        # 處理背景圖片上傳
        if 'background_image' in request.files:
            file = request.files['background_image']
            
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(f"{user_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                # 更新資料庫中的背景圖片路徑
                db.execute(
                    'UPDATE user_profiles SET background_image = ? WHERE user_id = ?',
                    (filename, user_id)
                )
        
        # 更新個人簡介
        db.execute(
            'UPDATE user_profiles SET bio = ? WHERE user_id = ?',
            (bio, user_id)
        )
        db.commit()
        
        flash('個人資料已更新')
        return redirect(url_for('profile'))
    
    # 獲取用戶的博客文章
    user_posts = db.execute(
        'SELECT id, title, substr(content, 1, 100) as preview, created_at '
        'FROM blog_posts WHERE user_id = ? '
        'ORDER BY created_at DESC',
        (user_id,)
    ).fetchall()
    
    return render_template('profile.html', profile=profile, user_posts=user_posts)

# 處理上傳文件的路由
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.cli.command('init-db')
def init_db_command():
    """初始化數據庫"""
    init_db()
    db = get_db()
    # 創建訪客帳戶
    try:
        db.execute(
            'INSERT OR IGNORE INTO users (id, username, password, is_admin) VALUES (1, "Guest", ?, 0)',
            (generate_password_hash("guestpassword"),)
        )
        # 檢查是否有管理員，如果沒有則創建默認管理員
        admin = db.execute('SELECT * FROM users WHERE is_admin = 1').fetchone()
        if admin is None:
            create_admin('admin', 'adminpassword')
        db.commit()
        print("數據庫已初始化")
    except Exception as e:
        print(f"初始化錯誤: {e}")

# 在主程序運行前初始化數據庫
def init_app(app):
    app.teardown_appcontext(lambda e: get_db().close() if e is not None else None)
    
    # 確保數據庫存在
    try:
        if not os.path.exists(app.config['DATABASE']):
            with app.app_context():
                init_db()
                db = get_db()
                # 創建訪客帳戶
                db.execute(
                    'INSERT OR IGNORE INTO users (id, username, password, is_admin) VALUES (1, "Guest", ?, 0)',
                    (generate_password_hash("guestpassword"),)
                )
                # 創建默認管理員
                admin = db.execute('SELECT * FROM users WHERE is_admin = 1').fetchone()
                if admin is None:
                    create_admin('admin', 'adminpassword')
                db.commit()
    except Exception as e:
        print(f"初始化錯誤: {e}")
        
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# 初始化應用
init_app(app)

if __name__ == '__main__':
    # 使用單一數據庫連接進行初始化
    with app.app_context():
        try:
            # 確保數據庫和表格存在
            init_db()
            
            # 使用同一個數據庫連接
            db = get_db()
            
            # 檢查是否有訪客帳戶，如果沒有則創建
            guest = db.execute('SELECT * FROM users WHERE id = 1').fetchone()
            if not guest:
                db.execute(
                    'INSERT INTO users (id, username, password, is_admin) VALUES (1, "Guest", ?, 0)',
                    (generate_password_hash("guestpassword"),)
                )
            
            # 檢查是否有管理員，如果沒有則創建
            admin = db.execute('SELECT * FROM users WHERE is_admin = 1').fetchone()
            if not admin:
                # 直接執行插入，而不是調用函數
                db.execute(
                    'INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)',
                    ('admin', generate_password_hash('adminpassword'))
                )
            
            db.commit()  # 只提交一次
            print("數據庫初始化完成")
            
        except Exception as e:
            print(f"初始化錯誤: {e}")
            # 繼續啟動應用程序
        
    # 啟動應用程序
    app.run(debug=True, host='0.0.0.0', port=10337)
