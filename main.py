from flask import Flask, render_template, request, redirect, url_for, session, flash
import pymysql.cursors
import uuid
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'super_secret_key_123'

# --- 1. DATABASE & SECURITY HELPERS ---

def get_db_connection():
    return pymysql.connect(
        host='localhost',
        user='root',
        password='',
        db='software engineering',
        cursorclass=pymysql.cursors.DictCursor
    )

def log_security_event(uID, action_description):
    connection = get_db_connection()
    try:
        with connection.cursor() as cur:
            log_id = str(uuid.uuid4())[:8] 
            sql = "INSERT INTO SECURITY_LOG (logID, userID, action, timestamp) VALUES (%s, %s, %s, %s)"
            cur.execute(sql, (log_id, uID, action_description, datetime.now()))
        connection.commit()
    finally:
        connection.close()

# --- 2. AUTHENTICATION & REGISTRATION ---

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login_submit', methods=['POST'])
def login_submit():
    uid = request.form.get('userid')
    pwd = request.form.get('password')

    connection = get_db_connection()
    try:
        with connection.cursor() as cur:
            cur.execute("SELECT * FROM user WHERE userID = %s", (uid,))
            user = cur.fetchone()
    finally:
        connection.close()

    if user and user['password'] == pwd:
        session['user_id'] = user['userID']
        session['full_name'] = user['fullName']
        session['role'] = user['role']
        
        log_security_event(uid, f"{user['role'].capitalize()} logged in successfully.")

        # REDIRECTION LOGIC: Updated to land on Overviews first
        if user['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif user['role'] == 'reviewer':
            return redirect(url_for('reviewer_dashboard'))
        elif user['role'] == 'committee':
            return redirect(url_for('committee_overview'))
        else:
            return redirect(url_for('student_dashboard'))
    else:
        flash("Invalid User ID or Password.")
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_security_event(session['user_id'], "User logged out.")
    session.clear()
    return redirect(url_for('index'))

@app.route('/register_page')
def show_register_page():
    return render_template('student_register.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.form
    connection = get_db_connection()
    try:
        with connection.cursor() as cur:
            cur.execute("INSERT INTO user (userID, fullName, password, email, role) VALUES (%s, %s, %s, %s, 'student')", 
                        (data['studentID'], data['fullName'], data['password'], data['email']))
            cur.execute("INSERT INTO student (studentID, faculty, course) VALUES (%s, %s, %s)", 
                        (data['studentID'], data['faculty'], data['course']))
        connection.commit()
        log_security_event(data['studentID'], "New student account registered.")
        flash("Registration successful! Please log in.")
        return redirect(url_for('index'))
    except Exception as e:
        connection.rollback()
        return f"Database Error: {e}"
    finally:
        connection.close()

# --- 3. PASSWORD RECOVERY SYSTEM ---

@app.route('/forgot_password')
def forgot_password_page():
    return render_template('forgot_password.html')

@app.route('/verify_identity', methods=['POST'])
def verify_identity():
    uid = request.form.get('userid')
    email = request.form.get('email')
    connection = get_db_connection()
    try:
        with connection.cursor() as cur:
            cur.execute("SELECT * FROM user WHERE userID = %s AND email = %s", (uid, email))
            user = cur.fetchone()
            if user:
                session['reset_user_id'] = uid
                return render_template('reset_password.html')
            else:
                flash("Error: User ID and Email do not match our records.")
                return redirect(url_for('forgot_password_page'))
    finally:
        connection.close()

@app.route('/update_password', methods=['POST'])
def update_password():
    if 'reset_user_id' not in session:
        return redirect(url_for('index'))
    new_pwd = request.form.get('new_password')
    confirm_pwd = request.form.get('confirm_password')
    user_id = session['reset_user_id']
    if new_pwd != confirm_pwd:
        flash("Passwords do not match!")
        return render_template('reset_password.html')
    connection = get_db_connection()
    try:
        with connection.cursor() as cur:
            cur.execute("UPDATE user SET password = %s WHERE userID = %s", (new_pwd, user_id))
        connection.commit()
        log_security_event(user_id, "User reset their password.")
        session.pop('reset_user_id', None)
        return render_template('reset_success.html') 
    finally:
        connection.close()

# --- 4. ADMIN ROUTES ---

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' in session and session.get('role') == 'admin':
        return render_template('admin_dashboard.html', admin_name=session['full_name'])
    return redirect(url_for('index'))

@app.route('/user_management')
def user_management():
    if 'user_id' in session and session.get('role') == 'admin':
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                # Only show users who are not 'Inactive'
                cur.execute("SELECT userID, fullName, email, role FROM user WHERE status != 'Inactive'")
                users_list = cur.fetchall()
            return render_template('user_management.html', 
                                   admin_name=session.get('full_name'), 
                                   users=users_list)
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/add_user')
def add_user():
    if 'user_id' in session and session.get('role') == 'admin':
        return render_template('add_user.html', admin_name=session.get('full_name'))
    return redirect(url_for('index'))

@app.route('/add_user_submit', methods=['POST'])
def add_user_submit():
    if 'user_id' in session and session.get('role') == 'admin':
        uid, name = request.form.get('userid'), request.form.get('fullname')
        email, pwd, role = request.form.get('email'), request.form.get('password'), request.form.get('role')
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                sql = "INSERT INTO user (userID, role, fullName, password, email) VALUES (%s, %s, %s, %s, %s)"
                cur.execute(sql, (uid, role, name, pwd, email))
            connection.commit()
            log_security_event(session['user_id'], f"Admin created {role} account: {uid}")
            return redirect(url_for('user_management'))
        except Exception as e:
            connection.rollback()
            return f"Error: {e}"
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/edit_user/<userid>')
def edit_user(userid):
    if 'user_id' in session and session.get('role') == 'admin':
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                # Use the 'userid' from the URL to fetch data
                cur.execute("SELECT * FROM user WHERE userID = %s", (userid,))
                user_data = cur.fetchone()
            if user_data:
                return render_template('edit_user.html', user=user_data, admin_name=session.get('full_name'))
            flash("User not found.")
            return redirect(url_for('user_management'))
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/delete_user/<userid>', methods=['POST'])
def delete_user(userid):
    if 'user_id' in session and session.get('role') == 'admin':
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                # SOFT DELETE: Update status instead of deleting row
                sql = "UPDATE user SET status = 'Inactive' WHERE userID = %s"
                cur.execute(sql, (userid,))
            connection.commit()
            
            log_security_event(session['user_id'], f"Admin deactivated account: {userid}")
            flash(f"Account {userid} has been deactivated.")
        except Exception as e:
            if connection: connection.rollback()
            flash(f"Error: {e}")
        finally:
            if connection: connection.close()
    return redirect(url_for('user_management'))

@app.route('/scholarship_manager')
def scholarship_manager():
    if 'user_id' in session and session.get('role') == 'admin':
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                # Filter out 'Archived' status
                cur.execute("SELECT * FROM scholarship WHERE status != 'Archived'")
                programs = cur.fetchall()
                
                today = datetime.now().date() # Get only the date
                
                for prog in programs:
                    if prog['deadline']:
                        # Ensure we compare date to date
                        deadline = prog['deadline']
                        if isinstance(deadline, datetime):
                            deadline = deadline.date()
                        
                        prog['is_expired'] = today > deadline
                        
            return render_template('scholarship_manager.html', 
                                   admin_name=session['full_name'], 
                                   scholarships=programs)
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/admin_manage_status/<sch_id>/<action>', methods=['POST'])
def admin_manage_status(sch_id, action):
    """
    Handles Admin lifecycle actions:
    - Close: Stop applications but keep visible as 'Closed'.
    - Archive: Soft-delete by hiding from all interfaces.
    """
    if 'user_id' in session and session.get('role') == 'admin':
        new_status = 'Closed' if action == 'close' else 'Archived'
            
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                cur.execute("UPDATE scholarship SET status = %s WHERE scholarshipID = %s", 
                            (new_status, sch_id))
            connection.commit()
            flash(f"Scholarship {sch_id} has been {new_status.lower()}.")
        except Exception as e:
            connection.rollback()
            flash(f"Error: {e}")
        finally:
            connection.close()
    return redirect(url_for('scholarship_manager'))

@app.route('/reviewer_assignment')
def reviewer_assignment():
    if 'user_id' in session and session.get('role') == 'admin':
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                sql = """
                    SELECT a.applicationID, u.fullName, u.userID, s.scholarshipName 
                    FROM application a
                    JOIN user u ON a.studentID = u.userID
                    JOIN scholarship s ON a.scholarshipID = s.scholarshipID
                    WHERE s.status != 'Archived'
                """
                cur.execute(sql)
                assignments = cur.fetchall()
            return render_template('reviewer_assignment.html', admin_name=session['full_name'], pending_tasks=assignments)
        finally:
            connection.close()
    return redirect(url_for('index'))

# --- 5. REVIEWER ROUTES ---

@app.route('/reviewer_dashboard')
def reviewer_dashboard(): 
    if 'user_id' in session and session.get('role') == 'reviewer':
        return render_template('reviewer_dashboard.html', reviewer_name=session['full_name'])
    return redirect(url_for('index'))

@app.route('/reviewer_queue')
def reviewer_queue():
    if 'user_id' in session and session.get('role') == 'reviewer':
        return render_template('reviewer_queue.html', reviewer_name=session['full_name'])
    return redirect(url_for('index'))

@app.route('/reviewer_assessment')
def reviewer_assessment():
    if 'user_id' in session and session.get('role') == 'reviewer':
        return render_template('reviewer_assessment.html', reviewer_name=session['full_name'])
    return redirect(url_for('index'))

@app.route('/scoring_history')
def scoring_history():
    if 'user_id' in session and session.get('role') == 'reviewer':
        return render_template('scoring_history.html', reviewer_name=session['full_name'])
    return redirect(url_for('index'))

# --- 6. COMMITTEE ROUTES ---

@app.route('/committee_overview')
def committee_overview():
    if 'user_id' in session and session.get('role') == 'committee':
        stats = {'total_apps': 1242, 'completion': '92%', 'funds': 'RM 500k'}
        return render_template('committee_overview.html', committee_name=session['full_name'], stats=stats)
    return redirect(url_for('index'))

@app.route('/committee_dashboard')
def committee_dashboard():
    if 'user_id' in session and session.get('role') == 'committee':
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                sql = "SELECT a.applicationID, u.fullName as applicantName, a.score, a.applicationStatus FROM application a JOIN user u ON a.studentID = u.userID WHERE a.score IS NOT NULL"
                cur.execute(sql)
                candidate_list = cur.fetchall()
            return render_template('committee_dashboard.html', committee_name=session['full_name'], candidates=candidate_list)
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/committee_portfolio')
def committee_portfolio():
    if 'user_id' in session and session.get('role') == 'committee':
        connection = get_db_connection()
        try:
            # Using DictCursor is required for the status logic in HTML
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                # Fetches all programs including Archived for the Committee view
                cur.execute("SELECT * FROM scholarship")
                programs = cur.fetchall()
            return render_template('committee_portfolio.html', 
                                   committee_name=session['full_name'], 
                                   scholarships=programs)
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/committee_calendar')
def committee_calendar():
    if 'user_id' in session and session.get('role') == 'committee':
        return render_template('committee_calendar.html', committee_name=session['full_name'])
    return redirect(url_for('index'))

# Unified route for creating new or editing existing scholarships
@app.route('/committee/manager')
@app.route('/edit_scholarship/<sch_id>')
def committee_manager(sch_id=None):
    if 'user_id' in session and session.get('role') == 'committee':
        scholarship_data = None
        if sch_id:
            connection = get_db_connection()
            try:
                with connection.cursor(pymysql.cursors.DictCursor) as cur:
                    sql = "SELECT * FROM scholarship WHERE scholarshipID = %s"
                    cur.execute(sql, (sch_id,))
                    scholarship_data = cur.fetchone()
            finally:
                connection.close()
        
        # Passes 'sch' as None for Create New, or as a dict for Edit
        return render_template('committee_manager.html', 
                               committee_name=session['full_name'], 
                               sch=scholarship_data)
    return redirect(url_for('index'))

@app.route('/add_scholarship_submit', methods=['POST'])
def add_scholarship_submit():
    if 'user_id' in session and session.get('role') == 'committee':
        # Determine status based on which button was clicked
        form_action = request.form.get('action')
        status = 'Published' if form_action == 'publish' else 'Draft'
        
        # Check if we are updating an existing record
        existing_id = request.form.get('scholarshipID')

        # Capture form data
        name = request.form.get('scholarshipName')
        amount = request.form.get('scholarshipAmount')
        criteria = request.form.get('scholarshipCriteria')
        deadline = request.form.get('deadline')
        faculty = request.form.get('faculty')
        slots = request.form.get('totalSlots')
        description = request.form.get('description')
        terms = request.form.get('termAndCondition')

        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                if existing_id:
                    # UPDATE existing record
                    sql = """UPDATE scholarship SET 
                             scholarshipName=%s, scholarshipCriteria=%s, deadline=%s, 
                             scholarshipAmount=%s, termAndCondition=%s, faculty=%s, 
                             totalSlots=%s, description=%s, status=%s 
                             WHERE scholarshipID=%s"""
                    cur.execute(sql, (name, criteria, deadline, amount, terms, 
                                      faculty, slots, description, status, existing_id))
                else:
                    # INSERT new record
                    sch_id = str(uuid.uuid4())[:8]
                    sql = """INSERT INTO scholarship 
                             (scholarshipID, scholarshipName, scholarshipCriteria, 
                              deadline, scholarshipAmount, termAndCondition, 
                              faculty, totalSlots, description, status) 
                             VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
                    cur.execute(sql, (sch_id, name, criteria, deadline, amount, 
                                      terms, faculty, slots, description, status))
                
            connection.commit()
            flash(f"Scholarship '{name}' {status.lower()} successfully.")
            return redirect(url_for('committee_portfolio'))
        except Exception as e:
            if connection: connection.rollback()
            return f"Error: {e}"
        finally:
            if connection: connection.close()
    return redirect(url_for('index'))

# --- 7. STUDENT ROUTES ---

@app.route('/student_dashboard')
def student_dashboard():
    if 'user_id' in session and session.get('role') == 'student':
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                # Fetch all published scholarships for the student list
                cur.execute("SELECT scholarshipID, scholarshipName, scholarshipCriteria FROM scholarship WHERE status = 'Published'")
                published_scholarships = cur.fetchall()
            return render_template('student_dashboard.html', 
                                   user_id=session['user_id'], 
                                   name=session['full_name'], 
                                   scholarships=published_scholarships)
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session or session.get('role') != 'student':
        return redirect(url_for('index'))

    connection = get_db_connection()
    try:
        with connection.cursor() as cur:
            if request.method == 'POST':
                # Capture manual academic updates
                cgpa = request.form.get('cgpa')
                credits = request.form.get('credits')

                # FIX: Update the 'student' table where these columns actually exist
                sql = "UPDATE student SET cgpa=%s, total_credits=%s WHERE studentID=%s"
                cur.execute(sql, (cgpa, credits, session['user_id']))
                connection.commit()
                
                flash("Academic records updated successfully!")
                return redirect(url_for('profile'))

            # JOIN logic to pull personal info (user table) and academic info (student table)
            sql = """
                SELECT u.fullName, u.email, s.* FROM user u 
                LEFT JOIN student s ON u.userID = s.studentID 
                WHERE u.userID = %s
            """
            cur.execute(sql, (session['user_id'],))
            student_data = cur.fetchone()
            
    finally:
        connection.close()

    return render_template('profile.html', 
                           student=student_data, 
                           user_id=session['user_id'], 
                           name=session['full_name'])

@app.route('/scholarship_detail/<sch_id>')
def scholarship_detail(sch_id):
    if 'user_id' in session and session.get('role') == 'student':
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                # Fetch details for the specific scholarship
                cur.execute("SELECT * FROM scholarship WHERE scholarshipID = %s", (sch_id,))
                scholarship = cur.fetchone()
                
                # Fetch student profile for eligibility checking
                cur.execute("SELECT * FROM student WHERE studentID = %s", (session['user_id'],))
                student_data = cur.fetchone()
                
            return render_template('scholarship_detail.html', 
                                   sch=scholarship, 
                                   student=student_data,
                                   user_id=session['user_id'], 
                                   name=session['full_name'])
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/tracking_hub')
def tracking_hub(): # Removed _view
    if 'user_id' in session and session.get('role') == 'student':
        return render_template('tracking_hub.html', user_id=session['user_id'], name=session['full_name'])
    return redirect(url_for('index'))

@app.route('/apply')
def application_form():  # This name MUST match your url_for()
    if 'user_id' in session and session.get('role') == 'student':
        return render_template('application_form.html')
    return redirect(url_for('login'))

@app.route('/scholarship_discovery')
def scholarship_discovery():
    if 'user_id' in session and session.get('role') == 'student':
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                # Fetches all published scholarships for the list
                cur.execute("SELECT * FROM scholarship WHERE status = 'Published'")
                published_list = cur.fetchall()
                
            return render_template('scholarship_discovery.html', 
                                   scholarships=published_list,
                                   user_id=session['user_id'], 
                                   name=session['full_name'])
        finally:
            connection.close()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)