# remove_specific_admin.py
import sqlite3

def remove_specific_admin(email):
    conn = sqlite3.connect('school.db')
    cur = conn.cursor()
    
    cur.execute("DELETE FROM admin_users WHERE email = ?", (email,))
    
    conn.commit()
    conn.close()
    print(f"Admin user '{email}' has been removed successfully!")

if __name__ == "__main__":
    email_to_remove = input("Enter the email of the admin to remove: ")
    remove_specific_admin(email_to_remove)