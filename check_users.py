import sqlite3

def check():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    print("--- 🔍 فحص المستخدمين في قاعدة البيانات ---")
    try:
        users = cursor.execute("SELECT id, username, password, is_admin FROM users").fetchall()
        if not users:
            print("❌ الجدول فارغ! لم يتم إنشاء أي مستخدم.")
        else:
            for user in users:
                print(f"✅ وجدنا المستخدم: {user[1]} | هل هو أدمن؟: {user[3]}")
                print(f"🔑 شكل الباسوورد المخزن: {user[2][:20]}...") # يطبع أول 20 حرف من التشفير
    except Exception as e:
        print(f"❌ خطأ في قراءة القاعدة: {e}")
        
    conn.close()

if __name__ == "__main__":
    check()