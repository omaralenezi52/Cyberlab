import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, json
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from collections import Counter
import sqlite3
import random

app = Flask(__name__)
app.secret_key = 'super_secret_key_change_me'

# إعدادات رفع الصور
UPLOAD_FOLDER = 'static/profile_pics'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ==================== دالة الاتصال مع الإصلاح الشامل للقاعدة ====================
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    
    # ميزة الإصلاح الذكي: التأكد من وجود كافة الأعمدة لتجنب أخطاء التنقل
    columns_to_add = [
        ('fullname', 'TEXT'),
        ('email', 'TEXT'),
        ('phone', 'TEXT'),
        ('age', 'INTEGER'),
        ('profile_pic', "TEXT DEFAULT 'default.png'"),
        ('score', 'INTEGER DEFAULT 0'),
        ('is_admin', 'INTEGER DEFAULT 0'),
        ('status', 'TEXT DEFAULT "active"')
    ]
    
    for col_name, col_type in columns_to_add:
        try:
            conn.execute(f'ALTER TABLE users ADD COLUMN {col_name} {col_type}')
            conn.commit()
        except sqlite3.OperationalError:
            pass 
            
    return conn

# ==================== دالة احتساب النقاط ====================
def award_points(user_id, challenge_id, points):
    conn = get_db_connection()
    solved = conn.execute('SELECT * FROM solved_challenges WHERE user_id = ? AND challenge_id = ?', 
                          (user_id, challenge_id)).fetchone()
    if not solved:
        conn.execute('UPDATE users SET score = score + ? WHERE id = ?', (points, user_id))
        conn.execute('INSERT INTO solved_challenges (user_id, challenge_id) VALUES (?, ?)', (user_id, challenge_id))
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False

# ==================== تسجيل الدخول ====================
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user:
            if user['status'] == 'banned':
                msg = "🚫 هذا الحساب محظور حالياً. يرجى التواصل مع الإدارة."
            elif check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']
                return redirect(url_for('admin_dashboard' if user['is_admin'] == 1 else 'profile'))
            else:
                msg = "خطأ في اسم المستخدم أو كلمة المرور!"
        else:
            msg = "خطأ في اسم المستخدم أو كلمة المرور!"
            
    return render_template('login.html', msg=msg)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ==================== التسجيل ====================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        fullname = request.form['fullname']
        email = request.form['email']
        phone = request.form['phone']
        age = request.form['age']
        
        hashed_password = generate_password_hash(password)
        
        conn = get_db_connection()
        try:
            conn.execute('''
                INSERT INTO users (username, password, fullname, email, phone, age, score, is_admin, status) 
                VALUES (?, ?, ?, ?, ?, ?, 0, 0, 'active')
            ''', (username, hashed_password, fullname, email, phone, age))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error: {e}")
            return "حدث خطأ! قد يكون اسم المستخدم مسجلاً مسبقاً."
    return render_template('register.html')

# ==================== المتصدرين (Leaderboard) ====================
@app.route('/leaderboard')
def leaderboard():
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users WHERE status="active" AND is_admin=0 ORDER BY score DESC').fetchall()
    conn.close()
    return render_template('leaderboard.html', users=users)

# ==================== الملف الشخصي (Profile) ====================
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db_connection()
    if request.method == 'POST':
        fullname = request.form.get('fullname')
        email = request.form.get('email')
        phone = request.form.get('phone')
        age = request.form.get('age')
        conn.execute('UPDATE users SET fullname = ?, email = ?, phone = ?, age = ? WHERE id = ?', 
                     (fullname, email, phone, age, session['user_id']))
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                conn.execute('UPDATE users SET profile_pic = ? WHERE id = ?', (filename, session['user_id']))
        conn.commit()
        flash('✅ تم تحديث الملف الشخصي بنجاح', 'success')

    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    solved = conn.execute('SELECT challenge_id FROM solved_challenges WHERE user_id = ?', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('profile.html', user=dict(user), solved_list=solved)

# ==================== لوحة تحكم الأدمن المتقدمة ====================
@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    if 'user_id' not in session or session.get('is_admin') != 1:
        return "⛔ غير مصرح لك بالدخول!", 403

    conn = get_db_connection()
    
    if request.method == 'POST' and 'update_score' in request.form:
        target_id = request.form.get('user_id')
        new_score = request.form.get('score')
        if target_id and new_score:
            conn.execute('UPDATE users SET score = ? WHERE id = ?', (new_score, target_id))
            conn.commit()
            flash('✅ تم تحديث النقاط بنجاح', 'success')

    users = conn.execute('SELECT * FROM users ORDER BY score DESC').fetchall()
    
    challenge_stats = conn.execute('''
        SELECT challenge_id, COUNT(*) as solve_count 
        FROM solved_challenges 
        GROUP BY challenge_id
        ORDER BY solve_count DESC
    ''').fetchall()

    total_users = conn.execute('SELECT COUNT(*) FROM users WHERE is_admin = 0').fetchone()[0]
    total_solves = conn.execute('SELECT COUNT(*) FROM solved_challenges').fetchone()[0]
    active_users = conn.execute('SELECT COUNT(*) FROM users WHERE status = \"active\" AND is_admin = 0').fetchone()[0]
    banned_users = total_users - active_users

    users_list = [dict(u) for u in users if not u['is_admin']]
    total_score = sum(u['score'] for u in users_list)
    avg_score = round(total_score / total_users, 1) if total_users > 0 else 0

    score_ranges = {'0-20': 0, '21-50': 0, '51-100': 0, '100+': 0}
    for user in users_list:
        score = user['score']
        if score <= 20: score_ranges['0-20'] += 1
        elif score <= 50: score_ranges['21-50'] += 1
        elif score <= 100: score_ranges['51-100'] += 1
        else: score_ranges['100+'] += 1

    top_players = sorted(users_list, key=lambda x: x['score'], reverse=True)[:5]
    top_names = [p['fullname'] or p['username'] for p in top_players]
    top_scores = [p['score'] for p in top_players]

    weekly_labels = ['السبت', 'الأحد', 'الاثنين', 'الثلاثاء', 'الأربعاء', 'الخميس', 'الجمعة']
    weekly_solves = [random.randint(max(1, total_solves//10), max(2, total_solves//5)) for _ in range(7)]
    weekly_registrations = [random.randint(0, max(2, total_users//10)) for _ in range(7)]

    # تم تحديث عدد التحديات ليصبح 10
    total_challenges = 10
    completion_rate = round((total_solves / (total_users * total_challenges)) * 100, 1) if total_users > 0 else 0

    labels = [row['challenge_id'] for row in challenge_stats]
    counts = [row['solve_count'] for row in challenge_stats]

    challenge_success_rates = {}
    for challenge in challenge_stats:
        rate = round((challenge['solve_count'] / total_users) * 100, 1) if total_users > 0 else 0
        challenge_success_rates[challenge['challenge_id']] = rate

    conn.close()
    
    return render_template('admin.html', users=users, total_users=total_users, active_users=active_users,
                           banned_users=banned_users, total_solves=total_solves, avg_score=avg_score,
                           completion_rate=completion_rate, labels=json.dumps(labels), counts=json.dumps(counts),
                           challenge_success_rates=json.dumps(challenge_success_rates),
                           score_ranges=json.dumps(score_ranges), top_names=json.dumps(top_names),
                           top_scores=json.dumps(top_scores), weekly_labels=json.dumps(weekly_labels),
                           weekly_solves=json.dumps(weekly_solves), weekly_registrations=json.dumps(weekly_registrations))

# ==================== دوال الإدارة المضافة لحل مشكلة BuildError ====================
@app.route('/toggle_user/<int:id>', methods=['POST'])
def toggle_user(id):
    if 'user_id' not in session or session.get('is_admin') != 1:
        return "Unauthorized", 403
    conn = get_db_connection()
    user = conn.execute('SELECT status FROM users WHERE id = ?', (id,)).fetchone()
    if user:
        new_status = 'banned' if user['status'] == 'active' else 'active'
        conn.execute('UPDATE users SET status = ? WHERE id = ?', (new_status, id))
        conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_user/<int:id>', methods=['POST'])
def delete_user(id):
    if 'user_id' not in session or session.get('is_admin') != 1:
        return "Unauthorized", 403
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))

# ==================== الصفحات الرئيسية ====================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/challenges')
def challenges_list():
    challenges = [
        {'name': 'SQL Injection', 'points': 10, 'url': 'sql_challenge', 'status': 'سهل', 'desc': 'تجاوز صفحة الدخول.', 'category': 'tech'},
        {'name': 'Ransomware', 'points': 20, 'url': 'ransomware_challenge', 'status': 'متوسط', 'desc': 'فك تشفير الملفات.', 'category': 'tech'},
        {'name': 'Linux Terminal', 'points': 30, 'url': 'terminal_challenge', 'status': 'متوسط', 'desc': 'محاكاة لنظام Linux للبحث عن ملفات مخفية.', 'category': 'tech'},
        {'name': 'Log Analysis', 'points': 40, 'url': 'forensics_challenge', 'status': 'متوسط', 'desc': 'حلل سجلات النظام لاكتشاف عنوان IP المهاجم.', 'category': 'tech'},
        {'name': 'Digital Maze', 'points': 150, 'url': 'os_challenge', 'status': 'مستحيل', 'desc': 'تحدي استقصائي معقد. سلسلة من الملفات المشفرة والرسائل الغامضة.', 'category': 'tech'},
        # تحدي الشبكات الجديد:
        {'name': 'Net Hunter', 'points': 200, 'url': 'net_challenge', 'status': 'خبير', 'desc': 'محاكاة لفحص الشبكات اللاسلكية واختراق الثغرات.', 'category': 'tech'},
        {'name': 'Phishing', 'points': 15, 'url': 'social_challenge', 'status': 'سهل', 'desc': 'اكتشاف الاحتيال الإلكتروني.', 'category': 'social'},
        {'name': 'The Bait', 'points': 15, 'url': 'baiting_challenge', 'status': 'سهل', 'desc': 'فخ الفلاش ميموري (Baiting).', 'category': 'social'},
        {'name': 'IT Support', 'points': 20, 'url': 'it_support_challenge', 'status': 'متوسط', 'desc': 'انتحال شخصية الدعم الفني.', 'category': 'social'}
    ]
    return render_template('challenges.html', challenges=challenges)

# ==================== تفاصيل التحديات ====================
@app.route('/net_challenge', methods=['GET', 'POST'])
def net_challenge():
    if 'user_id' not in session: return redirect(url_for('login'))
    msg = ""
    if request.method == 'POST':
        final_flag = request.form.get('flag')
        if final_flag == "NBU{WIFI_P3N3TRATOR_PRO_2026}":
            if award_points(session['user_id'], 'Net Hunter', 200):
                msg = "🏆 مذهل! أنت الآن خبير شبكات معتمد في NBU."
            else: msg = "⚠️ تم حل التحدي مسبقاً."
        else: msg = "❌ الرمز خاطئ. ركز في فحص المنافذ المفتوحة!"
    return render_template('net_challenge.html', msg=msg)

@app.route('/os_challenge', methods=['GET', 'POST'])
def os_challenge():
    if 'user_id' not in session: return redirect(url_for('login'))
    msg = ""
    if request.method == 'POST':
        secret_flag = request.form.get('flag')
        if secret_flag == "CTF{NBU_SYS_ADMIN_GOD_MODE_2026}":
            if award_points(session['user_id'], 'Digital Maze', 150):
                msg = "🔥 لا أصدق! لقد كسرت المتاهة المستحيلة!"
            else: msg = "⚠️ تم حل التحدي مسبقاً."
        else: msg = "❌ خطأ.. المتاهة تزداد تعقيداً، ركز في التفاصيل!"
    return render_template('os_challenge.html', msg=msg)

@app.route('/sql_challenge', methods=['GET', 'POST'])
def sql_challenge():
    msg = ""
    if request.method == 'POST':
        user_input = request.form.get('username')
        if user_input == "' OR 1=1 --":
            if 'user_id' in session:
                if award_points(session['user_id'], 'SQL Injection', 10):
                    msg = "✅ إجابة صحيحة!"
                else: msg = "⚠️ تم الحل مسبقاً."
        else: msg = "❌ خطأ!"     
    return render_template('sql_challenge.html', msg=msg)

@app.route('/terminal_challenge', methods=['GET', 'POST'])
def terminal_challenge():
    if 'user_id' not in session: return redirect(url_for('login'))
    msg = ""
    if request.method == 'POST':
        user_flag = request.form.get('flag')
        if user_flag == "NBU{Linux_Master_2026}":
            if award_points(session['user_id'], 'Linux Terminal', 30):
                msg = "✅ مذهل! تم إضافة 30 نقطة."
            else: msg = "⚠️ تم الحل مسبقاً."
        else: msg = "❌ خطأ!"
    return render_template('terminal_challenge.html', msg=msg)

@app.route('/forensics_challenge', methods=['GET', 'POST'])
def forensics_challenge():
    if 'user_id' not in session: return redirect(url_for('login'))
    msg = ""
    if request.method == 'POST':
        attacker_ip = request.form.get('flag')
        if attacker_ip == "192.168.1.44":
            if award_points(session['user_id'], 'Log Analysis', 40):
                msg = "✅ مذهل! لقد اكتشفت المهاجم بنجاح."
            else: msg = "⚠️ لقد حللت هذا التحدي مسبقاً."
        else: msg = "❌ الـ IP غير صحيح، راجع سجلات الوصول جيداً."
    return render_template('forensics_challenge.html', msg=msg)

@app.route('/ransomware_challenge', methods=['GET', 'POST'])
def ransomware_challenge():
    msg = ""
    if request.method == 'POST':
        if request.form.get('key') == "Tm9Nb3JlUmFuc29tMjAyNQ==":
            if 'user_id' in session:
                if award_points(session['user_id'], 'Ransomware', 20):
                    msg = "✅ أحسنت! تم فك تشفير الملفات."
                else: msg = "⚠️ لقد قمت بحل هذا التحدي مسبقاً."
        else: msg = "❌ المفتاح غير صحيح."
    return render_template('ransomware.html', msg=msg)

@app.route('/social_challenge', methods=['GET', 'POST'])
def social_challenge():
    msg = ""
    if request.method == 'POST':
        if request.form.get('answer') == 'phishing':
            if 'user_id' in session:
                if award_points(session['user_id'], 'Social Engineering', 15):
                    msg = "✅ إجابة صحيحة! هذا كان هجوم تصيد."
                else: msg = "⚠️ لقد قمت بحل هذا التحدي مسبقاً."
        else: msg = "❌ إجابة خاطئة."
    return render_template('social_engineering.html', msg=msg)

@app.route('/baiting_challenge', methods=['GET', 'POST'])
def baiting_challenge():
    msg = ""
    if request.method == 'POST':
        choice = request.form.get('choice')
        if choice == 'trap':
            if 'user_id' in session:
                if award_points(session['user_id'], 'The Bait', 15):
                    msg = "✅ ذكي جداً! لقد ميزت الفخ."
                else: msg = "⚠️ لقد قمت بحل هذا التحدي مسبقاً."
        else: msg = "❌ للأسف! لقد وقعت في الفخ."     
    return render_template('baiting_challenge.html', msg=msg)

@app.route('/it_support_challenge', methods=['GET', 'POST'])
def it_support_challenge():
    msg = ""
    if request.method == 'POST':
        answer = request.form.get('answer')
        if answer == 'official':
            if 'user_id' in session:
                if award_points(session['user_id'], 'IT Support', 20):
                    msg = "✅ صحيح! دائماً استخدم البوابات الرسمية."
                else: msg = "⚠️ لقد قمت بحل هذا التحدي مسبقاً."
        else: msg = "❌ خطأ! الرد على الإيميل هو ما يريده المهاجم."     
    return render_template('it_support.html', msg=msg)

if __name__ == '__main__':
    app.run(debug=True)