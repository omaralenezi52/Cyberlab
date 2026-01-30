import sqlite3

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # جدول المستخدمين
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            age INTEGER,
            profile_pic TEXT DEFAULT 'default.png',
            score INTEGER DEFAULT 0,
            is_admin INTEGER DEFAULT 0 
        )
    ''')

    # جدول التحديات المنجزة
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS solved_challenges (
            user_id INTEGER,
            challenge_id TEXT,
            PRIMARY KEY (user_id, challenge_id)
        )
    ''')
    
    # حساب الأدمن
    try:
        cursor.execute("INSERT INTO users (username, password, score, is_admin) VALUES (?, ?, ?, ?)", 
                       ('admin', '123456', 1000, 1))
        print("✅ تم إنشاء حساب الأدمن (admin/123456)")
    except:
        pass

    conn.commit()
    conn.close()
    print("✅ قاعدة البيانات جاهزة.")

if __name__ == '__main__':
    init_db()