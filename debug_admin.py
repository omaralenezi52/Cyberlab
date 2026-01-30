import sqlite3

def check_admin_status():
    print("--- 🕵️‍♂️ جاري فحص حساب الأدمن ---")
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # البحث عن الأدمن
    target_user = 'admin'
    user = cursor.execute("SELECT id, username, password, is_admin FROM users WHERE username = ?", (target_user,)).fetchone()
    
    if user:
        print(f"✅ الحساب موجود: {user[1]}")
        print(f"🔑 الباسوورد (المشفر): {user[2][:20]}...") # نعرض أول 20 حرف فقط
        print(f"👑 هل هو أدمن (is_admin)؟: {user[3]}")
        
        if user[3] == 1:
            print("نتيجة الفحص: الحساب سليم 100%، المشكلة في كود app.py أو المتصفح.")
        else:
            print("❌ المشكلة: هذا المستخدم ليس أدمن (القيمة 0)!")
    else:
        print(f"❌ المشكلة: المستخدم '{target_user}' غير موجود أصلاً في قاعدة البيانات!")
        
    conn.close()

if __name__ == "__main__":
    check_admin_status()