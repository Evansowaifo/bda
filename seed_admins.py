# seed_admins.py (run this once)
import sqlite3
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def seed_admin_users():
    conn = sqlite3.connect('school.db')
    cur = conn.cursor()
    
    admins = [
        ("evansowaifo@gmail.com", hash_password("dudebabe")),
        ("SalamiayoJobapp@gmail.com", hash_password("Deskat21@"))
    ]
    
    for email, pwd_hash in admins:
        cur.execute("INSERT OR IGNORE INTO admin_users (email, password_hash) VALUES (?, ?)", 
                   (email, pwd_hash))
    
    conn.commit()
    conn.close()
    print("Admin users seeded successfully!")

if __name__ == "__m