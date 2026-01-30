import sqlite3
from werkzeug.security import generate_password_hash
import os

def init_db():
    # Database file name
    db_file = 'database.db'

    # If the database exists, remove it to start fresh (ensures schema updates and encryption)
    if os.path.exists(db_file):
        os.remove(db_file)
        print("🗑️  Old database removed (to update structure).")

    # Connect and create the database
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    # 1. Create Users Table (with new columns: fullname, email, phone, age)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            fullname TEXT,
            email TEXT,
            phone TEXT,
            age INTEGER,
            profile_pic TEXT DEFAULT 'default.png',
            score INTEGER DEFAULT 0,
            is_admin INTEGER DEFAULT 0 
        )
    ''')

    # 2. Create Solved Challenges Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS solved_challenges (
            user_id INTEGER,
            challenge_id TEXT,
            PRIMARY KEY (user_id, challenge_id)
        )
    ''')
    
    # 3. Create Admin Account (With Encrypted/Hashed Password)
    # The password here is: 123456
    admin_password = "123456"
    hashed_admin_pw = generate_password_hash(admin_password)
    
    try:
        cursor.execute('''
            INSERT INTO users (username, password, fullname, email, phone, age, score, is_admin) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', ('admin', hashed_admin_pw, 'System Admin', 'admin@cyberlab.com', '0500000000', 30, 1000, 1))
        
        print(f"✅ Admin account created successfully!")
        print(f"👤 Username: admin")
        print(f"🔑 Password: {admin_password}")
        
    except Exception as e:
        print(f"❌ Error creating admin account: {e}")

    conn.commit()
    conn.close()
    print("🚀 Database is completely ready for action.")

if __name__ == '__main__':
    init_db()