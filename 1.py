# school_app_v6_complete_fixed.py
import streamlit as st
import sqlite3
import pandas as pd
import re
import html
import time
import threading
from datetime import date, datetime, timedelta
from contextlib import contextmanager
import shutil
import io
import hashlib

# Hide the deploy button and menu
st.markdown("""
<style>
    #MainMenu {visibility: hidden;}
    header {visibility: hidden;}
    .stDeployButton {display:none;}
    footer {visibility: hidden;}
    
    /* Make management tools at top more transparent */
    .management-tools {
        background-color: rgba(240, 242, 246, 0.8);
        padding: 15px;
        border-radius: 10px;
        margin: 10px 0;
        border: 1px solid #e0e0e0;
    }
    
    /* Style buttons better */
    .stButton button {
        margin: 2px 0;
    }
    
    /* Style logout button */
    .logout-btn {
        background-color: #ff4444 !important;
        color: white !important;
        border: 1px solid #cc0000 !important;
    }
    .logout-btn:hover {
        background-color: #cc0000 !important;
        border: 1px solid #990000 !important;
    }
    
    /* Style audit logs button */
    .audit-btn {
        background-color: #4CAF50 !important;
        color: white !important;
        border: 1px solid #45a049 !important;
    }
    .audit-btn:hover {
        background-color: #45a049 !important;
        border: 1px solid #3d8b40 !important;
    }
</style>
""", unsafe_allow_html=True)

# ---------------- CONFIG ----------------
st.set_page_config(
    page_title="School DB v6", 
    page_icon="🎓", 
    layout="wide", 
    initial_sidebar_state="expanded"
)
DB_PATH = "school.db"

# ---------------- ERROR HANDLING ----------------
def safe_db_operation(func):
    """Decorator for safe database operations"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint" in str(e):
                st.error("Duplicate entry found. Please check matric/receipt numbers.")
            else:
                st.error(f"Database integrity error: {str(e)}")
            return None
        except sqlite3.Error as e:
            st.error(f"Database error: {str(e)}")
            return None
        except Exception as e:
            st.error(f"Unexpected error: {str(e)}")
            return None
    return wrapper

class DatabaseError(Exception):
    """Custom database exception"""
    pass

# ---------------- DATABASE MANAGER WITH CONNECTION POOLING ----------------
class DatabaseManager:
    _local = threading.local()
    
    @contextmanager
    def get_connection(self):
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        try:
            yield self._local.conn
        except sqlite3.Error:
            self._local.conn.rollback()
            raise
        # Keep connection open for thread lifetime
    
    def close_connection(self):
        """Close connection if exists"""
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

db_manager = DatabaseManager()

def get_conn():
    """Backward compatibility function"""
    with db_manager.get_connection() as conn:
        return conn

# ---------------- AUDIT LOG SYSTEM ----------------
@safe_db_operation
def init_audit_log_table():
    """Initialize audit log table for tracking logins/logouts"""
    with db_manager.get_connection() as conn:
        cur = conn.cursor()
        
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                action TEXT NOT NULL,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT
            )
        """)
        
        # Create index for better performance
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_email ON audit_log(email)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)")
        
        conn.commit()

@safe_db_operation
def log_audit_event(email, action, ip_address=None, user_agent=None):
    """Log an audit event (login/logout)"""
    with db_manager.get_connection() as conn:
        cur = conn.cursor()
        
        cur.execute("""
            INSERT INTO audit_log (email, action, timestamp, ip_address, user_agent)
            VALUES (?, ?, datetime('now'), ?, ?)
        """, (email, action, ip_address, user_agent))
        
        conn.commit()

@safe_db_operation
def get_audit_logs(days=30):
    """Get recent audit logs"""
    with db_manager.get_connection() as conn:
        cutoff_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
        df = pd.read_sql("""
            SELECT email, action, timestamp, ip_address, user_agent
            FROM audit_log 
            WHERE timestamp > ?
            ORDER BY timestamp DESC
        """, conn, params=(cutoff_date,))
        return df

def get_client_info():
    """Get client IP and user agent (basic implementation)"""
    try:
        # Note: In Streamlit Cloud, real IP might not be available
        # This is a simplified version
        import streamlit.runtime.scriptrunner.script_run_context as script_context
        ctx = script_context.get_script_run_ctx()
        if ctx:
            # Try to get session info
            session_info = getattr(ctx, 'session_id', 'unknown')
            return f"session_{session_info}", "Streamlit App"
    except:
        pass
    return "unknown", "unknown"

# ---------------- IMPROVED TIME FILTERING ----------------
def get_time_periods():
    """Get comprehensive time periods for filtering"""
    today = date.today()
    current_year = today.year
    current_month = today.replace(day=1)
    last_month = (current_month - timedelta(days=1)).replace(day=1)
    
    periods = {
        "All Time": None,
        "Today": (today, today),
        "This Week": (today - timedelta(days=today.weekday()), today),
        "Last Week": (today - timedelta(days=today.weekday()+7), today - timedelta(days=today.weekday()+1)),
        "This Month": (current_month, today),
        "Last Month": (last_month, current_month - timedelta(days=1)),
        "This Year": (date(current_year, 1, 1), today),
        "Last Year": (date(current_year-1, 1, 1), date(current_year-1, 12, 31)),
    }
    return periods

def apply_time_filter(df, time_period, date_column):
    """Apply time filter to dataframe"""
    if time_period == "All Time" or time_period not in get_time_periods():
        return df
    
    start_date, end_date = get_time_periods()[time_period]
    
    if start_date and end_date:
        mask = (df[date_column] >= start_date.isoformat()) & (df[date_column] <= end_date.isoformat())
        return df[mask]
    return df

# ---------------- COMPLETION DATE FILTERING ----------------
def apply_completion_date_filter(df, filter_option):
    """Filter students based on completion date"""
    if filter_option == "Show All Students":
        return df
    
    # Check if completion_date column exists and has data
    if 'completion_date' not in df.columns or df['completion_date'].isna().all():
        st.warning("No completion dates available for filtering.")
        return df
    
    today = date.today().isoformat()
    
    try:
        if filter_option == "Exclude Completed Students":
            # Exclude students whose completion date has passed
            # Handle NaN values and ensure we only filter valid dates
            valid_dates_mask = df['completion_date'].notna()
            completed_mask = df['completion_date'] < today
            return df[~(valid_dates_mask & completed_mask)]
        
        elif filter_option == "Show Only Completed Students":
            # Show only students whose completion date has passed
            valid_dates_mask = df['completion_date'].notna()
            completed_mask = df['completion_date'] < today
            return df[valid_dates_mask & completed_mask]
        
        elif filter_option == "Show Students Completing Soon (30 days)":
            # Show students completing in the next 30 days
            future_date = (date.today() + timedelta(days=30)).isoformat()
            valid_dates_mask = df['completion_date'].notna()
            soon_mask = (df['completion_date'] >= today) & (df['completion_date'] <= future_date)
            return df[valid_dates_mask & soon_mask]
    
    except Exception as e:
        st.error(f"Error applying completion date filter: {str(e)}")
        return df
    
    return df

# ---------------- AUTHENTICATION & AUDIT ENHANCEMENTS ----------------
def hash_password(password):
    """Hash a password for storing."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    """Verify a stored password against one provided by user"""
    return hash_password(password) == hashed

@safe_db_operation
def init_admin_table():
    """Initialize admin table structure only - NO default users"""
    with db_manager.get_connection() as conn:
        cur = conn.cursor()
        
        # Create admin table if not exists (but don't populate it)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS admin_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

def authenticate_user(email, password):
    """Authenticate user credentials and log the login attempt"""
    with db_manager.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM admin_users WHERE email = ?", (email,))
        result = cur.fetchone()
        
        if result and verify_password(password, result[0]):
            # Log successful login
            ip_address, user_agent = get_client_info()
            log_audit_event(email, "LOGIN", ip_address, user_agent)
            return True
        else:
            # Log failed login attempt
            ip_address, user_agent = get_client_info()
            log_audit_event(email, "FAILED_LOGIN", ip_address, user_agent)
            return False

def logout_user():
    """Log the logout event and clear session"""
    if st.session_state.get("admin_email"):
        email = st.session_state.admin_email
        ip_address, user_agent = get_client_info()
        log_audit_event(email, "LOGOUT", ip_address, user_agent)
    
    # Clear session state
    st.session_state.authenticated = False
    st.session_state.admin_email = ""
    st.session_state.page = "home"

def login_page():
    """Display login page"""
    st.title("🏫 BDA School Management System")
    st.markdown("---")
    
    # Check if any admin users exist
    with db_manager.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM admin_users")
        admin_count = cur.fetchone()[0]
    
    if admin_count == 0:
        st.error("❌ No admin users found in database. Please run the seed_admins.py script first.")
        st.info("""
        **To set up admin users:**
        1. Run `python seed_admins.py` in your terminal
        2. Refresh this page
        3. Use the pre-configured admin credentials to login
        """)
        return
    
    with st.form("login_form"):
        st.subheader("Admin Login")
        email = st.text_input("Email", placeholder="Enter your email")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        
        submitted = st.form_submit_button("Login", use_container_width=True)
        
        if submitted:
            if not email or not password:
                st.error("Please enter both email and password")
            elif authenticate_user(email, password):
                st.session_state.authenticated = True
                st.session_state.admin_email = email
                st.success("Login successful!")
                time.sleep(1)
                st.rerun()
            else:
                st.error("Invalid email or password")

def check_authentication():
    """Check if user is authenticated"""
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    
    if not st.session_state.authenticated:
        login_page()
        st.stop()
    
    # Enhanced logout button in sidebar
    st.sidebar.markdown("---")
    st.sidebar.markdown(f"**Logged in as:** {st.session_state.admin_email}")
    
    col1, col2 = st.sidebar.columns([1, 1])
    with col1:
        if st.button("🚪 Logout", 
                    use_container_width=True, 
                    key="logout_btn",
                    on_click=logout_user):
            st.rerun()
    
    with col2:
        if st.button("📊 Audit Logs", 
                    use_container_width=True, 
                    key="audit_btn"):
            st.session_state.show_audit_logs = True

# ---------------- AUDIT LOGS PAGE ----------------
def show_audit_logs_page():
    """Display audit logs"""
    st.header("📊 System Audit Logs")
    st.subheader("Login/Logout History")
    
    # Time filter for audit logs
    col1, col2, col3 = st.columns([2, 2, 1])
    
    with col1:
        days_filter = st.selectbox(
            "Show logs for:",
            [7, 30, 90, 365],
            index=1,
            key="audit_days_filter"
        )
    
    with col2:
        action_filter = st.selectbox(
            "Filter by action:",
            ["All Actions", "LOGIN", "LOGOUT", "FAILED_LOGIN"],
            key="audit_action_filter"
        )
    
    with col3:
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()
    
    # Get audit logs
    audit_logs = get_audit_logs(days_filter)
    
    if audit_logs.empty:
        st.info("No audit logs found for the selected period.")
        return
    
    # Apply action filter
    if action_filter != "All Actions":
        audit_logs = audit_logs[audit_logs['action'] == action_filter]
    
    # Display statistics
    st.subheader("📈 Audit Statistics")
    total_events = len(audit_logs)
    logins = len(audit_logs[audit_logs['action'] == 'LOGIN'])
    logouts = len(audit_logs[audit_logs['action'] == 'LOGOUT'])
    failed_logins = len(audit_logs[audit_logs['action'] == 'FAILED_LOGIN'])
    
    stat_col1, stat_col2, stat_col3, stat_col4 = st.columns(4)
    
    with stat_col1:
        st.metric("Total Events", total_events)
    
    with stat_col2:
        st.metric("Successful Logins", logins)
    
    with stat_col3:
        st.metric("Logouts", logouts)
    
    with stat_col4:
        st.metric("Failed Logins", failed_logins)
    
    # Recent activity
    st.subheader("🕒 Recent Activity")
    
    # Group by date and action
    recent_activity = audit_logs.copy()
    recent_activity['date'] = pd.to_datetime(recent_activity['timestamp']).dt.date
    daily_activity = recent_activity.groupby(['date', 'action']).size().unstack(fill_value=0)
    
    if not daily_activity.empty:
        st.bar_chart(daily_activity)
    
    # Detailed log table
    st.subheader("📋 Detailed Audit Log")
    
    # Format the display
    display_logs = audit_logs.copy()
    display_logs['timestamp'] = pd.to_datetime(display_logs['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
    
    # Color code actions
    def color_action(action):
        if action == 'LOGIN':
            return 'color: green; font-weight: bold;'
        elif action == 'LOGOUT':
            return 'color: orange; font-weight: bold;'
        elif action == 'FAILED_LOGIN':
            return 'color: red; font-weight: bold;'
        return ''
    
    styled_logs = display_logs.style.map(
        lambda x: color_action(x) if x in ['LOGIN', 'LOGOUT', 'FAILED_LOGIN'] else '', 
        subset=['action']
    )
    
    st.dataframe(styled_logs, use_container_width=True)
    
    # Download button
    st.subheader("💾 Download Audit Logs")
    download_buttons(audit_logs, f"audit_logs_{days_filter}days")
    
    # Back button
    if st.button("⬅️ Back to Main", use_container_width=True):
        st.session_state.show_audit_logs = False
        st.rerun()

# ---------------- DATABASE INITIALIZATION & MIGRATIONS ----------------
@safe_db_operation
def init_db_and_migrate():
    """Initialize database with proper indexes and migrations"""
    with db_manager.get_connection() as conn:
        cur = conn.cursor()
        
        # Base tables
        cur.executescript("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            class_name TEXT,
            center TEXT,
            reg_date TEXT,
            start_date TEXT,
            completion_date TEXT,
            mat_no TEXT UNIQUE,
            phone TEXT,
            email TEXT,
            actual_amount REAL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER,
            amount_paid REAL,
            date TEXT,
            receipt_no TEXT UNIQUE,
            due_date TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER,
            subject TEXT,
            total_score REAL,
            term TEXT,
            session TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE
        );
        """)
        
        # Create indexes for performance
        cur.executescript("""
        CREATE INDEX IF NOT EXISTS idx_students_class ON students(class_name);
        CREATE INDEX IF NOT EXISTS idx_students_center ON students(center);
        CREATE INDEX IF NOT EXISTS idx_students_mat_no ON students(mat_no);
        CREATE INDEX IF NOT EXISTS idx_payments_student_id ON payments(student_id);
        CREATE INDEX IF NOT EXISTS idx_payments_date ON payments(date);
        CREATE INDEX IF NOT EXISTS idx_payments_due_date ON payments(due_date);
        CREATE INDEX IF NOT EXISTS idx_payments_receipt_no ON payments(receipt_no);
        CREATE INDEX IF NOT EXISTS idx_results_student_id ON results(student_id);
        """)
        
        # Migrations
        migrations = [
            "ALTER TABLE students ADD COLUMN actual_amount REAL DEFAULT 0",
            "ALTER TABLE payments ADD COLUMN receipt_no TEXT",
            "ALTER TABLE payments ADD COLUMN due_date TEXT",
            "ALTER TABLE students ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP",
            "ALTER TABLE students ADD COLUMN updated_at TEXT DEFAULT CURRENT_TIMESTAMP",
            "ALTER TABLE payments ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP",
            "ALTER TABLE results ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP"
        ]
        
        for migration in migrations:
            try:
                cur.execute(migration)
            except sqlite3.Error:
                pass  # Column likely already exists
        
        conn.commit()

# ---------------- BACKUP SYSTEM ----------------
@safe_db_operation
def backup_database():
    """Create a database backup with timestamp"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = f"backup_school_db_{timestamp}.db"
    
    try:
        # Force connection close for backup
        db_manager.close_connection()
        
        shutil.copy2(DB_PATH, backup_file)
        
        # Reinitialize connection
        init_db_and_migrate()
        
        return True, backup_file
    except Exception as e:
        return False, f"Backup failed: {str(e)}"

def restore_database(backup_file):
    """Restore database from backup"""
    try:
        db_manager.close_connection()
        shutil.copy2(backup_file, DB_PATH)
        init_db_and_migrate()
        return True, "Database restored successfully"
    except Exception as e:
        return False, f"Restore failed: {str(e)}"

# ---------------- BULK OPERATIONS ----------------
@safe_db_operation
def bulk_import_students(uploaded_file):
    """Bulk import students from CSV"""
    try:
        df = pd.read_csv(uploaded_file)
        required_columns = ['first_name', 'last_name', 'class_name']
        
        # Validate required columns
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            return False, f"Missing required columns: {', '.join(missing_columns)}"
        
        with db_manager.get_connection() as conn:
            cur = conn.cursor()
            success_count = 0
            errors = []
            
            for idx, row in df.iterrows():
                try:
                    # Validate data
                    validation_errors = validate_student_data(
                        row.get('first_name', ''), 
                        row.get('last_name', ''),
                        row.get('phone', ''),
                        row.get('email', ''),
                        row.get('mat_no', '')
                    )
                    
                    if validation_errors:
                        errors.append(f"Row {idx+1}: {', '.join(validation_errors)}")
                        continue
                    
                    # Insert student
                    cur.execute("""
                        INSERT INTO students 
                        (first_name, last_name, class_name, center, reg_date, start_date, 
                         completion_date, mat_no, phone, email, actual_amount)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        sanitize_input(row.get('first_name', '')),
                        sanitize_input(row.get('last_name', '')),
                        sanitize_input(row.get('class_name', '')),
                        sanitize_input(row.get('center', '')),
                        row.get('reg_date', date.today().isoformat()),
                        row.get('start_date', date.today().isoformat()),
                        row.get('completion_date', date.today().isoformat()),
                        sanitize_input(row.get('mat_no', '')),
                        sanitize_input(row.get('phone', '')),
                        sanitize_input(row.get('email', '')),
                        float(row.get('actual_amount', 0))
                    ))
                    success_count += 1
                    
                except sqlite3.IntegrityError:
                    errors.append(f"Row {idx+1}: Duplicate matric number or other constraint violation")
                except Exception as e:
                    errors.append(f"Row {idx+1}: {str(e)}")
            
            conn.commit()
            
            result_message = f"Successfully imported {success_count} students"
            if errors:
                result_message += f". {len(errors)} errors occurred"
                
            return True, result_message, errors
            
    except Exception as e:
        return False, f"Import failed: {str(e)}", []

@safe_db_operation
def export_students_to_csv():
    """Export all students to CSV"""
    with db_manager.get_connection() as conn:
        df = pd.read_sql("SELECT * FROM students ORDER BY class_name, first_name", conn)
        return df.to_csv(index=False)

# ---------------- LOADING STATES & UX ----------------
def with_loading(message="Processing..."):
    """Decorator for showing loading states"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            with st.spinner(message):
                time.sleep(0.3)  # Minimal delay for better UX
                result = func(*args, **kwargs)
                return result
        return wrapper
    return decorator

def show_success(message, duration=3):
    """Show success message that auto-dismisses"""
    success_placeholder = st.empty()
    success_placeholder.success(message)
    time.sleep(duration)
    success_placeholder.empty()

def confirm_action(message, key_suffix):
    """Get confirmation for destructive actions"""
    return st.checkbox(message, key=f"confirm_{key_suffix}")

# ---------------- SESSION STATE MANAGEMENT ----------------
def init_session_state():
    """Initialize all session state variables"""
    if "page" not in st.session_state:
        st.session_state["page"] = "home"
    if "editing_student" not in st.session_state:
        st.session_state["editing_student"] = None
    if "editing_payment" not in st.session_state:
        st.session_state["editing_payment"] = None
    if "del_confirm" not in st.session_state:
        st.session_state["del_confirm"] = {}
    if "backup_created" not in st.session_state:
        st.session_state["backup_created"] = False
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
    if "admin_email" not in st.session_state:
        st.session_state["admin_email"] = ""
    if "show_audit_logs" not in st.session_state:
        st.session_state["show_audit_logs"] = False

def set_page(p):
    st.session_state["page"] = p

# ---------------- DATA FETCHING FUNCTIONS ----------------
@safe_db_operation
@with_loading("Loading students...")
def fetch_students_df():
    with db_manager.get_connection() as conn:
        df = pd.read_sql("SELECT * FROM students ORDER BY class_name, first_name", conn)
        # Ensure completion_date is properly formatted
        if 'completion_date' in df.columns:
            df['completion_date'] = pd.to_datetime(df['completion_date'], errors='coerce').dt.date
        return df

@safe_db_operation
def students_map_for_select():
    df = fetch_students_df()
    if df.empty:
        return {}
    return {f"{r['first_name']} {r['last_name']} (id:{r['id']})": r['id'] for _, r in df.iterrows()}

@safe_db_operation
def fetch_payments_df():
    with db_manager.get_connection() as conn:
        df = pd.read_sql("""
            SELECT p.*, s.first_name || ' ' || s.last_name AS full_name, s.class_name
            FROM payments p
            JOIN students s ON p.student_id = s.id
            ORDER BY p.date DESC
        """, conn)
        return df

# ---------------- UTILITY FUNCTIONS ----------------
def download_buttons(df, filename):
    if df is None or df.empty:
        return
        
    csv = df.to_csv(index=False)
    json_s = df.to_json(orient="records", force_ascii=False)
    
    col1, col2 = st.columns([1,1])
    with col1:
        st.download_button("Download CSV", data=csv, file_name=f"{filename}.csv", mime="text/csv")
    with col2:
        st.download_button("Download JSON", data=json_s, file_name=f"{filename}.json", mime="application/json")

# ---------------- MANAGEMENT TOOLS AT TOP ----------------
def show_management_tools():
    """Show backup/restore and bulk operations at top of page"""
    st.markdown('<div class="management-tools">', unsafe_allow_html=True)
    st.subheader("🔧 Database Management Tools")
    
    # Create tabs for different management functions
    tab1, tab2 = st.tabs(["💾 Backup & Restore", "📦 Bulk Operations"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Backup Database**")
            if st.button("Create Backup Now", use_container_width=True, key="backup_btn"):
                with st.spinner("Creating backup..."):
                    success, result = backup_database()
                    if success:
                        st.success(f"✅ Backup created: {result}")
                        st.session_state.backup_created = True
                    else:
                        st.error(f"❌ {result}")
        
        with col2:
            st.write("**Restore Database**")
            restore_file = st.file_uploader("Choose backup file", type=['db'], key="restore_uploader", label_visibility="collapsed")
            
            if restore_file:
                st.warning("⚠️ This will replace ALL current data!")
                if st.button("Restore from Backup", use_container_width=True, key="restore_btn"):
                    # Save uploaded file temporarily
                    with open("temp_restore.db", "wb") as f:
                        f.write(restore_file.getvalue())
                    
                    success, message = restore_database("temp_restore.db")
                    if success:
                        st.success(f"✅ {message}")
                        st.rerun()
                    else:
                        st.error(f"❌ {message}")
    
    with tab2:
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Bulk Import Students**")
            uploaded_file = st.file_uploader("Choose CSV file", type=['csv'], key="bulk_import", label_visibility="collapsed")
            
            if uploaded_file:
                st.info("📋 CSV should contain: first_name, last_name, class_name")
                
                if st.button("Import Students from CSV", use_container_width=True, key="import_btn"):
                    with st.spinner("Importing students..."):
                        success, message, errors = bulk_import_students(uploaded_file)
                        if success:
                            st.success(f"✅ {message}")
                            if errors:
                                with st.expander("⚠️ View Import Errors"):
                                    for error in errors[:10]:
                                        st.error(error)
                        else:
                            st.error(f"❌ {message}")
        
        with col2:
            st.write("**Export Students**")
            if st.button("Download All Students as CSV", use_container_width=True, key="export_btn"):
                with st.spinner("Preparing download..."):
                    csv_data = export_students_to_csv()
                    st.download_button(
                        "⬇️ Download CSV Now",
                        data=csv_data,
                        file_name=f"students_export_{date.today().isoformat()}.csv",
                        mime="text/csv",
                        use_container_width=True,
                        key="download_csv_btn"
                    )
    
    st.markdown('</div>', unsafe_allow_html=True)

# ---------------- SECURITY & VALIDATION ----------------
def sanitize_input(text):
    """Basic input sanitization to prevent XSS"""
    if text is None:
        return ""
    return html.escape(str(text).strip())

def validate_student_data(first_name, last_name, phone, email, mat_no=None):
    """Comprehensive student data validation"""
    errors = []
    
    if not first_name or not last_name:
        errors.append("First and last name are required")
    
    if phone and not validate_phone(phone):
        errors.append("Invalid phone format. Use international format: +1234567890")
    
    if email and not validate_email(email):
        errors.append("Invalid email format")
    
    # Validate matric number format if provided
    if mat_no and not re.match(r'^[A-Za-z0-9\-_]+$', mat_no):
        errors.append("Matric number can only contain letters, numbers, hyphens, and underscores")
    
    return errors

def validate_payment_data(amount, receipt_no=None):
    """Validate payment data"""
    errors = []
    
    if amount <= 0:
        errors.append("Amount must be greater than 0")
    
    if receipt_no and not re.match(r'^[A-Za-z0-9\-_/]+$', receipt_no):
        errors.append("Receipt number contains invalid characters")
    
    return errors

def validate_phone(phone):
    return bool(re.match(r"^\+?\d{7,15}$", phone)) if phone else True

def validate_email(email):
    return bool(re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email)) if email else True

# ---------------- MISSING PAYMENT STATISTICS FUNCTION ----------------
def display_payment_statistics(df, time_period="All Time"):
    """Display comprehensive payment statistics"""
    st.subheader("💰 Payment Statistics Overview")
    
    if time_period != "All Time":
        df_filtered = apply_time_filter(df, time_period, "date")
    else:
        df_filtered = df
    
    total_payments = len(df_filtered)
    total_amount = df_filtered['amount_paid'].sum() if not df_filtered.empty else 0
    
    # Payment distribution by class
    if not df_filtered.empty:
        class_payments = df_filtered.groupby('class_name')['amount_paid'].agg(['sum', 'count']).reset_index()
        class_payments.columns = ['Class', 'Total Amount', 'Payment Count']
    else:
        class_payments = pd.DataFrame()
    
    # Display metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Payments", total_payments)
    
    with col2:
        st.metric("Total Amount", f"₦{total_amount:,.2f}")
    
    with col3:
        avg_per_payment = total_amount / total_payments if total_payments > 0 else 0
        st.metric("Average Payment", f"₦{avg_per_payment:,.2f}")
    
    with col4:
        unique_classes = len(class_payments) if not class_payments.empty else 0
        st.metric("Classes with Payments", unique_classes)
    
    # Class-wise payment statistics
    if not class_payments.empty:
        st.write("**Payments by Class:**")
        cols = st.columns(min(6, len(class_payments)))
        for idx, row in class_payments.iterrows():
            if idx < len(cols):
                with cols[idx]:
                    st.metric(
                        f"{row['Class']}",
                        f"₦{row['Total Amount']:,.0f}",
                        delta=f"{row['Payment Count']} payments"
                    )

# ---------------- IMPROVED STATISTICS ----------------
def display_comprehensive_statistics(df, time_period="All Time"):
    """Display comprehensive student statistics with time-based analysis"""
    st.subheader("📊 Comprehensive Student Statistics")
    
    if time_period != "All Time":
        df_filtered = apply_time_filter(df, time_period, "reg_date")
        total_students = len(df_filtered)
        total_all_students = len(df)
    else:
        df_filtered = df
        total_students = len(df_filtered)
        total_all_students = total_students
    
    # Calculate growth metrics
    if time_period != "All Time":
        previous_period = get_previous_period(time_period)
        df_previous = apply_time_filter(df, previous_period, "reg_date")
        previous_students = len(df_previous) if df_previous is not None else 0
        growth = total_students - previous_students
        growth_percentage = (growth / previous_students * 100) if previous_students > 0 else 0
    else:
        growth = 0
        growth_percentage = 0
    
    class_distribution = df_filtered['class_name'].value_counts()
    center_distribution = df_filtered['center'].value_counts()
    
    # Display comprehensive metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Total Students", 
            total_students,
            delta=f"{growth} ({growth_percentage:+.1f}%)" if time_period != "All Time" else None,
            delta_color="normal" if growth >= 0 else "inverse"
        )
    
    with col2:
        unique_classes = len(class_distribution)
        st.metric("Number of Classes", unique_classes)
    
    with col3:
        unique_centers = len(center_distribution)
        st.metric("Number of Centers", unique_centers)
    
    with col4:
        avg_per_class = total_students / unique_classes if unique_classes > 0 else 0
        st.metric("Avg Students/Class", f"{avg_per_class:.1f}")
    
    # Time-based analysis
    st.subheader("⏰ Time-Based Analysis")
    time_col1, time_col2, time_col3 = st.columns(3)
    
    with time_col1:
        # Weekly analysis
        weekly_data = get_students_by_week(df_filtered)
        st.metric("This Week", weekly_data.get('current_week', 0))
    
    with time_col2:
        # Monthly analysis  
        monthly_data = get_students_by_month(df_filtered)
        st.metric("This Month", monthly_data.get('current_month', 0))
    
    with time_col3:
        # Yearly analysis
        yearly_data = get_students_by_year(df_filtered)
        st.metric("This Year", yearly_data.get('current_year', 0))
    
    # Class distribution in columns
    if not class_distribution.empty:
        st.write("**📚 Students by Class:**")
        cols = st.columns(min(6, len(class_distribution)))
        for idx, (class_name, count) in enumerate(class_distribution.items()):
            if idx < len(cols):
                with cols[idx]:
                    percentage = (count / total_students * 100) if total_students > 0 else 0
                    st.metric(class_name, count, delta=f"{percentage:.1f}%")

def get_previous_period(current_period):
    """Get the previous time period for comparison"""
    periods = {
        "Today": "Yesterday",
        "This Week": "Last Week", 
        "Last Week": "Two Weeks Ago",
        "This Month": "Last Month",
        "Last Month": "Two Months Ago",
        "This Year": "Last Year",
        "Last Year": "Two Years Ago"
    }
    return periods.get(current_period, "All Time")

def get_students_by_week(df):
    """Get student counts by week"""
    if df.empty:
        return {'current_week': 0}
    
    df['reg_date'] = pd.to_datetime(df['reg_date'])
    current_week = datetime.now().isocalendar()[1]
    current_week_students = len(df[df['reg_date'].dt.isocalendar().week == current_week])
    
    return {'current_week': current_week_students}

def get_students_by_month(df):
    """Get student counts by month"""
    if df.empty:
        return {'current_month': 0}
    
    df['reg_date'] = pd.to_datetime(df['reg_date'])
    current_month = datetime.now().month
    current_month_students = len(df[df['reg_date'].dt.month == current_month])
    
    return {'current_month': current_month_students}

def get_students_by_year(df):
    """Get student counts by year"""
    if df.empty:
        return {'current_year': 0}
    
    df['reg_date'] = pd.to_datetime(df['reg_date'])
    current_year = datetime.now().year
    current_year_students = len(df[df['reg_date'].dt.year == current_year])
    
    return {'current_year': current_year_students}

# ---------------- OVERDUE MANAGEMENT ----------------
@safe_db_operation
def get_overdue_students_data():
    """Get comprehensive overdue students dataset"""
    with db_manager.get_connection() as conn:
        # Get students with payment details
        df = pd.read_sql("""
            SELECT 
                s.id AS student_id,
                s.first_name || ' ' || s.last_name AS full_name,
                s.class_name,
                s.center,
                s.phone,
                s.email,
                COALESCE(s.actual_amount, 0) AS actual_amount,
                COALESCE(SUM(p.amount_paid), 0) AS total_paid,
                MAX(p.due_date) AS latest_due_date,
                COUNT(p.id) AS payment_count
            FROM students s
            LEFT JOIN payments p ON s.id = p.student_id
            GROUP BY s.id
            HAVING actual_amount > total_paid
            ORDER BY s.class_name, s.first_name
        """, conn)
        
        # Get individual overdue payments
        overdue_payments = pd.read_sql("""
            SELECT 
                p.student_id,
                p.amount_paid,
                p.date,
                p.receipt_no,
                p.due_date,
                s.first_name || ' ' || s.last_name AS full_name,
                s.class_name
            FROM payments p
            JOIN students s ON p.student_id = s.id
            WHERE p.due_date IS NOT NULL 
            AND p.due_date < date('now')
            ORDER BY p.due_date
        """, conn)
        
        # Calculate overdue amounts and status
        if not df.empty:
            df["amount_owing"] = (df["actual_amount"] - df["total_paid"]).clip(lower=0)
            df["payment_status"] = df.apply(
                lambda r: "Fully Paid" if r["total_paid"] >= r["actual_amount"] else "Owing", 
                axis=1
            )
            
            # Mark overdue status
            today = date.today().isoformat()
            df["has_overdue"] = False
            
            for idx, row in df.iterrows():
                student_id = row["student_id"]
                student_overdue = overdue_payments[overdue_payments["student_id"] == student_id]
                df.at[idx, "has_overdue"] = not student_overdue.empty and row["payment_status"] == "Owing"
        
        return df, overdue_payments

def display_overdue_alerts():
    """Display comprehensive overdue alerts"""
    overdue_students, overdue_payments = get_overdue_students_data()
    
    if overdue_students.empty or overdue_students['has_overdue'].sum() == 0:
        return
    
    overdue_count = overdue_students['has_overdue'].sum()
    total_overdue_amount = overdue_students[overdue_students['has_overdue']]['amount_owing'].sum()
    
    # Main overdue alert
    st.error(f"🚨 **OVERDUE PAYMENTS ALERT** - {overdue_count} students with overdue payments totaling ₦{total_overdue_amount:,.2f}")
    
    # Detailed overdue information
    with st.expander("📋 View Overdue Details", expanded=True):
        # Overdue by class
        overdue_by_class = overdue_students[overdue_students['has_overdue']].groupby('class_name').agg({
            'student_id': 'count',
            'amount_owing': 'sum'
        }).reset_index()
        
        overdue_by_class.columns = ['Class', 'Overdue Students', 'Total Overdue Amount']
        
        if not overdue_by_class.empty:
            st.write("**Overdue by Class:**")
            cols = st.columns(min(6, len(overdue_by_class)))
            for idx, row in overdue_by_class.iterrows():
                if idx < len(cols):
                    with cols[idx]:
                        st.metric(
                            row['Class'],
                            f"₦{row['Total Overdue Amount']:,.0f}",
                            delta=f"{row['Overdue Students']} students"
                        )
        
        # Individual overdue students
        st.write("**Overdue Students:**")
        for _, student in overdue_students[overdue_students['has_overdue']].iterrows():
            col1, col2, col3 = st.columns([3, 2, 2])
            with col1:
                st.warning(f"**{student['full_name']}** - {student['class_name']}")
            with col2:
                st.write(f"Owing: ₦{student['amount_owing']:,.2f}")
            with col3:
                st.write(f"Phone: {student.get('phone', 'N/A')}")
    
    # Download overdue dataset
    overdue_download_df = overdue_students[overdue_students['has_overdue']][[
        'full_name', 'class_name', 'center', 'actual_amount', 'total_paid', 
        'amount_owing', 'payment_count', 'phone', 'email'
    ]]
    
    if not overdue_download_df.empty:
        st.subheader("💾 Download Overdue Students Dataset")
        download_buttons(overdue_download_df, "overdue_students_report")

# ---------------- PAYMENT SUMMARY FUNCTION ----------------
@safe_db_operation
def display_payment_summary():
    st.header("💰 Payment Summary - Student Balances")
    
    # Display overdue alerts at the top
    display_overdue_alerts()
    
    with db_manager.get_connection() as conn:
        # Get payment summary with due date information
        df = pd.read_sql("""
            SELECT 
                s.id AS student_id,
                s.first_name || ' ' || s.last_name AS full_name,
                s.class_name,
                s.center,
                s.reg_date,
                s.completion_date,
                COALESCE(s.actual_amount, 0) AS actual_amount,
                COALESCE(SUM(p.amount_paid), 0) AS total_paid,
                COUNT(p.id) AS payment_count,
                MAX(p.due_date) AS latest_due_date,
                MAX(p.date) as latest_payment_date
            FROM students s
            LEFT JOIN payments p ON s.id = p.student_id
            GROUP BY s.id
            ORDER BY s.class_name, s.first_name
        """, conn)
        
        # Get individual payments for detailed view
        payments_detail = pd.read_sql("""
            SELECT 
                p.id,
                p.student_id,
                p.amount_paid,
                p.date,
                p.receipt_no,
                p.due_date,
                s.first_name || ' ' || s.last_name AS full_name,
                s.class_name
            FROM payments p
            JOIN students s ON p.student_id = s.id
            ORDER BY p.student_id, p.date
        """, conn)
    
    if df.empty:
        st.info("No student records found.")
        return
    
    # Calculate owing amounts and status
    df["amount_owing"] = (df["actual_amount"] - df["total_paid"]).clip(lower=0)
    df["payment_status"] = df.apply(
        lambda r: "Fully Paid" if r["total_paid"] >= r["actual_amount"] else "Owing", 
        axis=1
    )
    
    # Check for overdue payments
    today = date.today().isoformat()
    df["has_overdue"] = False
    
    for idx, row in df.iterrows():
        student_id = row["student_id"]
        student_payments = payments_detail[payments_detail["student_id"] == student_id]
        if not student_payments.empty:
            # Check if any due date has passed and payment is not fully made
            overdue_payments = student_payments[
                (student_payments["due_date"] < today) & 
                (row["payment_status"] == "Owing")
            ]
            df.at[idx, "has_overdue"] = not overdue_payments.empty
    
    # Time-based filtering
    st.subheader("⏰ Time-Based Filtering")
    time_col1, time_col2, time_col3 = st.columns(3)
    
    with time_col1:
        time_period = st.selectbox(
            "Filter by Time Period:",
            list(get_time_periods().keys()),
            key="payment_time_filter"
        )
    
    with time_col2:
        # Class filter
        classes = ["All"] + sorted(df["class_name"].dropna().unique().tolist())
        class_filter = st.selectbox("Filter by Class", classes, key="payment_class_filter")
    
    with time_col3:
        # Completion date filter for payment summary
        completion_filter_options = [
            "Show All Students",
            "Exclude Completed Students", 
            "Show Only Completed Students",
            "Show Students Completing Soon (30 days)"
        ]
        completion_filter = st.selectbox(
            "Filter by Completion Date",
            completion_filter_options,
            key="payment_completion_filter"
        )
    
    # Apply time filter to payments and student data
    payments_filtered_by_time = apply_time_filter(payments_detail, time_period, "date")
    
    # Apply filters to main dataframe
    filtered_df = df.copy()
    
    if time_period != "All Time":
        # Filter students based on their payment activity in the time period
        students_with_payments_in_period = payments_filtered_by_time['student_id'].unique()
        filtered_df = filtered_df[filtered_df['student_id'].isin(students_with_payments_in_period)]
    
    if class_filter != "All":
        filtered_df = filtered_df[filtered_df["class_name"] == class_filter]
    
    # Apply completion date filter
    filtered_df = apply_completion_date_filter(filtered_df, completion_filter)
    
    # Calculate total amounts for the new metrics
    total_amount_owing = filtered_df["amount_owing"].sum()
    total_amount_overdue = filtered_df[filtered_df["has_overdue"] == True]["amount_owing"].sum()
    
    # Display comprehensive statistics
    st.subheader("💰 Payment Statistics Overview")
    
    # Apply time filter for payment statistics
    if time_period != "All Time":
        payments_filtered = apply_time_filter(payments_detail, time_period, "date")
    else:
        payments_filtered = payments_detail
    
    total_payments = len(payments_filtered)
    total_paid_amount = payments_filtered['amount_paid'].sum() if not payments_filtered.empty else 0
    
    # Display metrics with time-filtered amounts
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Payments", total_payments)
    
    with col2:
        st.metric("Total Paid Amount", f"₦{total_paid_amount:,.2f}")
    
    with col3:
        st.metric("Total Amount Owing", f"₦{total_amount_owing:,.2f}")
    
    with col4:
        st.metric("Total Amount Overdue", f"₦{total_amount_overdue:,.2f}")
    
    # Class-wise payment statistics
    if not payments_filtered.empty:
        class_payments = payments_filtered.groupby('class_name')['amount_paid'].agg(['sum', 'count']).reset_index()
        class_payments.columns = ['Class', 'Total Amount', 'Payment Count']
        
        if not class_payments.empty:
            st.write("**Payments by Class:**")
            cols = st.columns(min(6, len(class_payments)))
            for idx, row in class_payments.iterrows():
                if idx < len(cols):
                    with cols[idx]:
                        st.metric(
                            f"{row['Class']}",
                            f"₦{row['Total Amount']:,.0f}",
                            delta=f"{row['Payment Count']} payments"
                        )
    
    # Summary statistics for filtered data
    total_students = len(filtered_df)
    fully_paid = len(filtered_df[filtered_df["payment_status"] == "Fully Paid"])
    owing_students = len(filtered_df[filtered_df["payment_status"] == "Owing"])
    overdue_students = len(filtered_df[filtered_df["has_overdue"] == True])
    total_owed_filtered = filtered_df["amount_owing"].sum()
    total_paid_period = payments_filtered_by_time['amount_paid'].sum() if not payments_filtered_by_time.empty else 0
    
    # Display summary cards
    st.subheader("📊 Payment Overview")
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric("Total Students", total_students)
    with col2:
        st.metric("Fully Paid", fully_paid)
    with col3:
        st.metric("Owing", owing_students)
    with col4:
        st.metric("Overdue", overdue_students)
    with col5:
        st.metric(f"Total Paid ({time_period})", f"₦{total_paid_period:,.2f}")
    
    # Additional filter options
    st.subheader("🎯 Advanced Filtering")
    filter_col1, filter_col2, filter_col3 = st.columns(3)
    
    with filter_col1:
        status_filter = st.selectbox(
            "Payment Status",
            ["All", "Fully Paid", "Owing", "Overdue"],
            key="payment_status_filter"
        )
    
    with filter_col2:
        centers = ["All"] + sorted(filtered_df["center"].dropna().unique().tolist())
        center_filter = st.selectbox("Center", centers, key="payment_center_filter")
    
    with filter_col3:
        # Amount owing range
        max_owing = filtered_df["amount_owing"].max() if not filtered_df.empty else 0
        owing_range = st.slider(
            "Amount Owing Range (₦)",
            0.0,
            float(max(100000, max_owing)),
            (0.0, float(max(100000, max_owing))),
            step=1000.0,
            key="payment_owing_filter"
        )
            
    # Apply advanced filters
    if status_filter == "Fully Paid":
        filtered_df = filtered_df[filtered_df["payment_status"] == "Fully Paid"]
    elif status_filter == "Owing":
        filtered_df = filtered_df[filtered_df["payment_status"] == "Owing"]
    elif status_filter == "Overdue":
        filtered_df = filtered_df[filtered_df["has_overdue"] == True]
    
    if center_filter != "All":
        filtered_df = filtered_df[filtered_df["center"] == center_filter]
    
    # Apply amount owing filter
    filtered_df = filtered_df[
        (filtered_df["amount_owing"] >= owing_range[0]) & 
        (filtered_df["amount_owing"] <= owing_range[1])
    ]
    
    # Display detailed table
    st.subheader("📋 Student Payment Details")
    
    if filtered_df.empty:
        st.info("No students match the selected filters.")
    else:
        # Format the display dataframe
        display_df = filtered_df[[
            "full_name", "class_name", "center", "actual_amount", 
            "total_paid", "amount_owing", "payment_status", "payment_count", "has_overdue"
        ]].copy()
        
        display_df.columns = [
            "Student Name", "Class", "Center", "Total Amount (₦)", 
            "Total Paid (₦)", "Amount Owing (₦)", "Status", "Payment Count", "Is Overdue"
        ]
        
        # Format currency columns
        for col in ["Total Amount (₦)", "Total Paid (₦)", "Amount Owing (₦)"]:
            display_df[col] = display_df[col].apply(lambda x: f"₦{x:,.2f}")
        
        # Highlight overdue rows
        def highlight_overdue(row):
            if row["Is Overdue"]:
                return ['background-color: #ffcccc'] * len(row)
            return [''] * len(row)
        
        styled_df = display_df.style.apply(highlight_overdue, axis=1)
        st.dataframe(styled_df, use_container_width=True)
        
        # Download buttons
        st.subheader("💾 Download Data")
        download_buttons(filtered_df, f"payment_summary_{time_period}_{class_filter}_{status_filter}")

# ---------------- PAGE COMPONENTS ----------------
def show_add_student_page():
    st.header("🧒 Add Student")
    with st.form("add_student_form", clear_on_submit=True):
        st.subheader("Basic Information")
        first = st.text_input("First name*")
        last = st.text_input("Last name*")
        cls = st.selectbox("Class*", [f"Primary {i}" for i in range(1,7)])
        center = st.text_input("Center (e.g., Ikorodu)")
        mat_no = st.text_input("Matric No (optional, unique)")
        actual_amount = st.number_input("Actual Amount (₦)", min_value=0.0, step=1000.0, value=0.0)

        st.subheader("Dates")
        reg_date = st.date_input("Date of Registration", value=date.today())
        start_date = st.date_input("Starting Date", value=date.today())
        completion_date = st.date_input("Expected Date of Completion", value=date.today())

        st.subheader("Contact")
        phone = st.text_input("Phone (optional)")
        email = st.text_input("Email (optional)")

        submitted = st.form_submit_button("Save Student")
        if submitted:
            # Validate data
            validation_errors = validate_student_data(first, last, phone, email, mat_no)
            
            if validation_errors:
                for error in validation_errors:
                    st.error(error)
            else:
                # Sanitize inputs
                first_safe = sanitize_input(first)
                last_safe = sanitize_input(last)
                center_safe = sanitize_input(center)
                mat_no_safe = sanitize_input(mat_no)
                phone_safe = sanitize_input(phone)
                email_safe = sanitize_input(email)
                
                @safe_db_operation
                @with_loading("Saving student...")
                def save_student():
                    with db_manager.get_connection() as conn:
                        cur = conn.cursor()
                        # Check mat uniqueness
                        if mat_no_safe:
                            cur.execute("SELECT COUNT(*) FROM students WHERE mat_no = ?", (mat_no_safe,))
                            if cur.fetchone()[0] > 0:
                                raise DatabaseError("Matric number already exists.")
                        
                        cur.execute("""
                            INSERT INTO students
                            (first_name, last_name, class_name, center, reg_date, start_date, 
                             completion_date, mat_no, phone, email, actual_amount)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (first_safe, last_safe, cls, center_safe,
                              reg_date.isoformat(), start_date.isoformat(), completion_date.isoformat(),
                              mat_no_safe, phone_safe, email_safe, float(actual_amount)))
                        conn.commit()
                        return True
                
                result = save_student()
                if result:
                    show_success(f"Added {first_safe} {last_safe}.")
                else:
                    st.error("Failed to save student.")

    # Complete student database display
    st.subheader("📋 Complete Student Database")
    df_students = fetch_students_df()
    if df_students.empty:
        st.info("No students yet.")
    else:
        st.dataframe(df_students)
        download_buttons(df_students, "student_summary")

def show_add_payment_page():
    st.header("💰 Add Payment")
    smap = students_map_for_select()
    if not smap:
        st.warning("No students. Add students first.")
    else:
        with st.form("add_payment_form", clear_on_submit=True):
            student_label = st.selectbox("Student", list(smap.keys()))
            sid = smap[student_label]
            amount = st.number_input("Amount Paid (₦)*", min_value=0.0, step=100.0)
            pay_date = st.date_input("Payment Date*", value=date.today())
            receipt_no = st.text_input("Receipt No (optional, must be unique if provided)")
            due_date = st.date_input("Due Date (optional)", value=date.today())
            
            submitted = st.form_submit_button("Save Payment")
            if submitted:
                # Validate payment data
                validation_errors = validate_payment_data(amount, receipt_no)
                
                if validation_errors:
                    for error in validation_errors:
                        st.error(error)
                else:
                    @safe_db_operation
                    @with_loading("Recording payment...")
                    def save_payment():
                        with db_manager.get_connection() as conn:
                            cur = conn.cursor()
                            if receipt_no:
                                cur.execute("SELECT COUNT(*) FROM payments WHERE receipt_no = ?", (receipt_no.strip(),))
                                if cur.fetchone()[0] > 0:
                                    raise DatabaseError("Receipt number already exists.")
                            
                            cur.execute("""
                                INSERT INTO payments (student_id, amount_paid, date, receipt_no, due_date)
                                VALUES (?, ?, ?, ?, ?)
                            """, (sid, float(amount), pay_date.isoformat(), receipt_no.strip(), due_date.isoformat()))
                            conn.commit()
                            return True
                    
                    result = save_payment()
                    if result:
                        show_success("Payment recorded successfully!")
                    else:
                        st.error("Failed to record payment.")

    # Live payments display
    st.subheader("Payments (live)")
    payments_df = fetch_payments_df()
    if payments_df.empty:
        st.info("No payments yet.")
    else:
        st.dataframe(payments_df)
        download_buttons(payments_df, "individual_payment_records")

def show_view_students_page():
    st.header("📋 Student Summary — Inline Edit / Delete")
    df = fetch_students_df()
    
    # IMPROVED Time-based filtering with completion date filter
    st.subheader("⏰ Advanced Time Filtering")
    time_col1, time_col2, time_col3 = st.columns(3)
    
    with time_col1:
        time_period = st.selectbox(
            "Filter by Registration Date:",
            list(get_time_periods().keys()),
            key="student_time_filter"
        )
    
    with time_col2:
        classes = ["All Classes"] + sorted(df["class_name"].dropna().unique().tolist()) if not df.empty else ["All Classes"]
        class_filter = st.selectbox("Filter by Class", classes, key="student_class_filter")
    
    with time_col3:
        # Completion date filter
        completion_filter_options = [
            "Show All Students",
            "Exclude Completed Students", 
            "Show Only Completed Students",
            "Show Students Completing Soon (30 days)"
        ]
        completion_filter = st.selectbox(
            "Filter by Completion Date",
            completion_filter_options,
            key="student_completion_filter"
        )
    
    # Apply filters
    df_filtered = apply_time_filter(df, time_period, "reg_date")
    
    if class_filter != "All Classes":
        df_filtered = df_filtered[df_filtered["class_name"] == class_filter]
    
    # Apply completion date filter
    df_filtered = apply_completion_date_filter(df_filtered, completion_filter)
    
    # Display IMPROVED comprehensive statistics
    display_comprehensive_statistics(df_filtered, time_period)
    
    if df_filtered.empty:
        st.info("No students found matching your filters.")
        return
    
    # Download button
    st.subheader("💾 Download Filtered Data")
    download_buttons(df_filtered, f"student_summary_{time_period}_{class_filter}")
    
    # Student list with editing
    st.subheader("👥 Student List")
    
    # Header row
    hdr_cols = st.columns([1,1,1,1,1,1,1,1,1])
    heads = ["ID","Name","Class","MatNo","Amount","Phone","Email","Center","Actions"]
    for c,h in zip(hdr_cols, heads):
        c.markdown(f"**{h}**")

    for _, row in df_filtered.iterrows():
        rid = int(row["id"])
        is_editing = (st.session_state["editing_student"] == rid)
        cols = st.columns([0.5,2,1.2,1,1,1.2,1.2,1,1.2])
        
        # ID
        cols[0].write(rid)
        
        # Name or edit inputs
        if is_editing:
            new_first = cols[1].text_input("First", value=row["first_name"], key=f"sf_{rid}")
            new_last = cols[2].text_input("Last", value=row["last_name"], key=f"sl_{rid}")
            new_class = cols[3].selectbox("Class", [f"Primary {i}" for i in range(1,7)], 
                                        index=(int(row["class_name"].split()[-1])-1) if row["class_name"] and "Primary" in str(row["class_name"]) else 0, 
                                        key=f"sc_{rid}")
            new_mat = cols[4].text_input("MatNo", value=row.get("mat_no","") or "", key=f"sm_{rid}")
            new_actual = cols[5].number_input("Actual", value=float(row.get("actual_amount") or 0.0), min_value=0.0, step=100.0, key=f"sa_{rid}")
            new_phone = cols[6].text_input("Phone", value=row.get("phone","") or "", key=f"sp_{rid}")
            new_email = cols[7].text_input("Email", value=row.get("email","") or "", key=f"se_{rid}")
            new_center = cols[8].text_input("Center", value=row.get("center","") or "", key=f"sct_{rid}")
            
            # Actions: save / cancel
            action_col1, action_col2 = st.columns(2)
            with action_col1:
                if st.button("💾 Save", key=f"save_s_{rid}", use_container_width=True):
                    # Validate
                    validation_errors = validate_student_data(new_first, new_last, new_phone, new_email, new_mat)
                    
                    if validation_errors:
                        for error in validation_errors:
                            st.error(error)
                    else:
                        @safe_db_operation
                        def update_student():
                            with db_manager.get_connection() as conn:
                                cur = conn.cursor()
                                cur.execute("""
                                    UPDATE students
                                    SET first_name=?, last_name=?, class_name=?, mat_no=?, 
                                        actual_amount=?, phone=?, email=?, center=?, updated_at=CURRENT_TIMESTAMP
                                    WHERE id=?
                                """, (sanitize_input(new_first), sanitize_input(new_last), new_class, 
                                      sanitize_input(new_mat), float(new_actual), sanitize_input(new_phone), 
                                      sanitize_input(new_email), sanitize_input(new_center), rid))
                                conn.commit()
                                return True
                        
                        if update_student():
                            st.session_state["editing_student"] = None
                            st.rerun()
                        else:
                            st.error("Failed to update student.")
            
            with action_col2:
                if st.button("✖ Cancel", key=f"cancel_s_{rid}", use_container_width=True):
                    st.session_state["editing_student"] = None
                    st.rerun()
        else:
            # Show fields
            cols[1].write(f"{row['first_name']} {row['last_name']}")
            cols[2].write(row.get("class_name",""))
            cols[3].write(row.get("mat_no","") or "")
            cols[4].write(row.get("actual_amount",0))
            cols[5].write(row.get("phone","") or "")
            cols[6].write(row.get("email","") or "")
            cols[7].write(row.get("center","") or "")
            
            # Actions: edit / delete
            action_col1, action_col2 = st.columns(2)
            with action_col1:
                if st.button("✏️ Edit", key=f"edit_s_{rid}", use_container_width=True):
                    st.session_state["editing_student"] = rid
                    st.rerun()
            with action_col2:
                if st.button("🗑 Delete", key=f"del_s_{rid}", use_container_width=True):
                    st.session_state["del_confirm"][f"student_{rid}"] = True

        # Deletion confirmation
        if st.session_state["del_confirm"].get(f"student_{rid}"):
            st.warning("Confirm delete student and all associated payments?")
            conf_col1, conf_col2, conf_col3 = st.columns([1,1,4])
            
            with conf_col1:
                if st.button("✅ Yes", key=f"confirm_del_s_{rid}", use_container_width=True):
                    @safe_db_operation
                    def delete_student():
                        with db_manager.get_connection() as conn:
                            cur = conn.cursor()
                            cur.execute("DELETE FROM students WHERE id=?", (rid,))
                            conn.commit()
                            return True
                    
                    if delete_student():
                        st.session_state["del_confirm"].pop(f"student_{rid}", None)
                        show_success("Student deleted successfully!")
                        st.rerun()
                    else:
                        st.error("Failed to delete student.")
            
            with conf_col2:
                if st.button("❌ Cancel", key=f"cancel_del_s_{rid}", use_container_width=True):
                    st.session_state["del_confirm"].pop(f"student_{rid}", None)
                    st.rerun()

def show_view_payments_page():
    view_option = st.radio(
        "Select Payment View:",
        ["📊 Payment Summary with Balances", "📄 Individual Payment Records"],
        horizontal=True,
        key="payment_view_option"
    )
    
    if view_option == "📊 Payment Summary with Balances":
        display_payment_summary()
    else:
        st.header("📄 Individual Payment Records — Inline Edit / Delete")
        payments = fetch_payments_df()

        if payments.empty:
            st.info("No payments found.")
        else:
            # Time-based filtering
            st.subheader("⏰ Time-Based Filtering")
            time_col1, time_col2, time_col3 = st.columns(3)
            
            with time_col1:
                time_period = st.selectbox(
                    "Filter by Payment Date:",
                    list(get_time_periods().keys()),
                    key="individual_payment_time_filter"
                )
            
            with time_col2:
                search_name = st.text_input("Search by student name:", placeholder="Enter first or last name...", key="payment_search")
            
            with time_col3:
                class_filter = st.selectbox(
                    "Filter by class:",
                    ["All Classes"] + sorted(payments["class_name"].dropna().unique().tolist()),
                    key="individual_payment_class_filter"
                )
            
            # Apply filters
            filtered_payments = apply_time_filter(payments, time_period, "date")
            
            if search_name:
                search_lower = search_name.lower()
                filtered_payments = filtered_payments[
                    filtered_payments["full_name"].str.lower().str.contains(search_lower, na=False)
                ]
            
            if class_filter != "All Classes":
                filtered_payments = filtered_payments[filtered_payments["class_name"] == class_filter]
            
            if filtered_payments.empty:
                st.warning("No payments match your search criteria.")
                st.info("Showing all payments instead:")
                filtered_payments = payments
            
            # Display statistics
            display_payment_statistics(filtered_payments, time_period)
            
            # Download button
            st.subheader("💾 Download Individual Payment Records")
            download_buttons(filtered_payments, f"individual_payment_records_{time_period}")
            
            # Header
            hdr = st.columns([1,2,1,1,1,1,1,1])
            heads = ["ID","Student","Class","Amount","Date","Receipt","Due Date","Actions"]
            for c,h in zip(hdr, heads):
                c.markdown(f"**{h}**")

            for _, p in filtered_payments.iterrows():
                pid = int(p["id"])
                is_editing = (st.session_state["editing_payment"] == pid)
                cols = st.columns([0.6,2,1,1,1.2,1.2,1,1])
                
                cols[0].write(pid)
                
                if is_editing:
                    new_amount = cols[3].number_input("Amt", value=float(p["amount_paid"] or 0.0), min_value=0.0, step=50.0, key=f"pay_amt_{pid}")
                    try:
                        d_default = datetime.fromisoformat(p["date"]).date() if p["date"] else date.today()
                    except Exception:
                        d_default = date.today()
                    new_date = cols[4].date_input("Date", value=d_default, key=f"pay_date_{pid}")
                    new_receipt = cols[5].text_input("Receipt", value=p.get("receipt_no","") or "", key=f"pay_rc_{pid}")
                    try:
                        due_default = datetime.fromisoformat(p["due_date"]).date() if p["due_date"] else date.today()
                    except Exception:
                        due_default = date.today()
                    new_due = cols[6].date_input("Due", value=due_default, key=f"pay_due_{pid}")

                    # Actions
                    action_col1, action_col2 = st.columns(2)
                    with action_col1:
                        if st.button("💾 Save", key=f"save_pay_{pid}", use_container_width=True):
                            validation_errors = validate_payment_data(new_amount, new_receipt)
                            
                            if validation_errors:
                                for error in validation_errors:
                                    st.error(error)
                            else:
                                @safe_db_operation
                                def update_payment():
                                    with db_manager.get_connection() as conn:
                                        cur = conn.cursor()
                                        if new_receipt:
                                            cur.execute("SELECT COUNT(*) FROM payments WHERE receipt_no = ? AND id <> ?", 
                                                       (new_receipt.strip(), pid))
                                            if cur.fetchone()[0] > 0:
                                                raise DatabaseError("Receipt already used by another payment.")
                                        
                                        cur.execute("UPDATE payments SET amount_paid=?, date=?, receipt_no=?, due_date=? WHERE id=?",
                                                   (float(new_amount), new_date.isoformat(), new_receipt.strip(), new_due.isoformat(), pid))
                                        conn.commit()
                                        return True
                                
                                if update_payment():
                                    st.session_state["editing_payment"] = None
                                    st.rerun()
                                else:
                                    st.error("Failed to update payment.")
                    
                    with action_col2:
                        if st.button("✖ Cancel", key=f"cancel_pay_{pid}", use_container_width=True):
                            st.session_state["editing_payment"] = None
                            st.rerun()
                else:
                    cols[1].write(p["full_name"])
                    cols[2].write(p["class_name"])
                    cols[3].write(p["amount_paid"])
                    cols[4].write(p["date"])
                    cols[5].write(p.get("receipt_no","") or "")
                    cols[6].write(p.get("due_date","") or "")
                    
                    # Actions
                    action_col1, action_col2 = st.columns(2)
                    with action_col1:
                        if st.button("✏️ Edit", key=f"edit_pay_{pid}", use_container_width=True):
                            st.session_state["editing_payment"] = pid
                            st.rerun()
                    with action_col2:
                        if st.button("🗑 Delete", key=f"del_pay_{pid}", use_container_width=True):
                            st.session_state["del_confirm"][f"payment_{pid}"] = True

                # Deletion confirmation
                if st.session_state["del_confirm"].get(f"payment_{pid}"):
                    st.warning("Confirm delete this payment record?")
                    conf_col1, conf_col2, conf_col3 = st.columns([1,1,4])
                    
                    with conf_col1:
                        if st.button("✅ Yes", key=f"confirm_del_pay_{pid}", use_container_width=True):
                            @safe_db_operation
                            def delete_payment():
                                with db_manager.get_connection() as conn:
                                    cur = conn.cursor()
                                    cur.execute("DELETE FROM payments WHERE id=?", (pid,))
                                    conn.commit()
                                    return True
                            
                            if delete_payment():
                                st.session_state["del_confirm"].pop(f"payment_{pid}", None)
                                show_success("Payment deleted successfully!")
                                st.rerun()
                            else:
                                st.error("Failed to delete payment.")
                    
                    with conf_col2:
                        if st.button("❌ Cancel", key=f"cancel_del_pay_{pid}", use_container_width=True):
                            st.session_state["del_confirm"].pop(f"payment_{pid}", None)
                            st.rerun()

def show_home_page():
    st.header("🏠 School Database Overview")
    
    # Get basic statistics
    students_df = fetch_students_df()
    payments_df = fetch_payments_df()
    
    # Display overview metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_students = len(students_df)
        st.metric("Total Students", total_students)
    
    with col2:
        total_payments = len(payments_df)
        total_payment_amount = payments_df['amount_paid'].sum() if not payments_df.empty else 0
        st.metric("Total Payments", total_payments, delta=f"₦{total_payment_amount:,.0f}")
    
    with col3:
        # Check for overdue
        overdue_students, _ = get_overdue_students_data()
        overdue_count = overdue_students['has_overdue'].sum() if not overdue_students.empty else 0
        st.metric("Overdue Students", overdue_count, delta_color="inverse")
    
    with col4:
        unique_classes = students_df['class_name'].nunique() if not students_df.empty else 0
        st.metric("Active Classes", unique_classes)
    
    # Display overdue alerts
    display_overdue_alerts()
    
    # Quick actions
    st.subheader("🚀 Quick Actions")
    qcol1, qcol2, qcol3, qcol4 = st.columns(4)
    
    with qcol1:
        if st.button("🧒 Add New Student", use_container_width=True, key="home_add_student"):
            set_page("add_student")
    with qcol2:
        if st.button("💰 Record Payment", use_container_width=True, key="home_add_payment"):
            set_page("add_payment")
    with qcol3:
        if st.button("📋 View All Students", use_container_width=True, key="home_view_students"):
            set_page("view_students")
    with qcol4:
        if st.button("📊 Payment Summary", use_container_width=True, key="home_view_payments"):
            set_page("view_payments")
    
    st.write("---")
    st.write("Choose an action above or use the navigation buttons. Click Edit on any row to edit inline.")

# ---------------- MAIN APPLICATION ----------------
def main():
    """Main application function"""
    # Initialize everything
    init_session_state()
    init_db_and_migrate()
    init_admin_table()  # Only creates table structure, no default users
    init_audit_log_table()  # Initialize audit log system
    
    # Check if we should show audit logs
    if st.session_state.get("show_audit_logs"):
        show_audit_logs_page()
        return
    
    # Check authentication
    check_authentication()
    
    # Header with admin info and enhanced logout + audit buttons
    col1, col2, col3 = st.columns([3, 1, 1])
    with col1:
        st.title("🏫 BDA School Management System")
        st.write(f"**Welcome, {st.session_state.admin_email}!**")
    with col2:
        if st.button("📊 Audit Logs", 
                    use_container_width=True, 
                    key="header_audit_btn",
                    type="secondary"):
            st.session_state.show_audit_logs = True
            st.rerun()
    with col3:
        if st.button("🚪 Logout", 
                    use_container_width=True, 
                    key="header_logout_btn",
                    on_click=logout_user):
            st.rerun()
    
    # Show management tools at top of page
    show_management_tools()
    
    # Main navigation
    st.header("Navigation")
    c1, c2, c3, c4 = st.columns(4)
    
    with c1:
        if st.button("🧒 Add Student", use_container_width=True, key="nav_add_student"):
            set_page("add_student")
    with c2:
        if st.button("💰 Add Payment", use_container_width=True, key="nav_add_payment"):
            set_page("add_payment")
    with c3:
        if st.button("📋 Student Summary", use_container_width=True, key="nav_view_students"):
            set_page("view_students")
    with c4:
        if st.button("📊 Payment Summary", use_container_width=True, key="nav_view_payments"):
            set_page("view_payments")
    
    st.markdown("---")
    
    # Page routing
    if st.session_state["page"] == "add_student":
        show_add_student_page()
    elif st.session_state["page"] == "add_payment":
        show_add_payment_page()
    elif st.session_state["page"] == "view_students":
        show_view_students_page()
    elif st.session_state["page"] == "view_payments":
        show_view_payments_page()
    else:
        show_home_page()

# Run the application
if __name__ == "__main__":
    main()
