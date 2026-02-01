from flask import Flask, render_template, request, redirect, url_for, session, flash
import pymysql.cursors
import uuid
from datetime import datetime
import os
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.secret_key = 'super_secret_key_123'

import os
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

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
            # 1. Insert into USER table
            cur.execute("INSERT INTO user (userID, fullName, password, email, role, status) VALUES (%s, %s, %s, %s, 'student', 'Active')", 
                        (data['studentID'], data['fullName'], data['password'], data['email']))
            
            # 2. Insert into STUDENT table including Address and DOB
            cur.execute("INSERT INTO student (studentID, faculty, course, address, dob) VALUES (%s, %s, %s, %s, %s)", 
                        (data['studentID'], data['faculty'], data['course'], data['address'], data['dob']))
            
            
        connection.commit()
        flash("Registration successful!")
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
    # 1. Security check: Only Admins can access
    if 'user_id' in session and session.get('role') == 'admin':
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                # 2. Modified SQL: Sort by deadline descending to see latest updates first
                # Filter out 'Archived' status as requested
                cur.execute("SELECT * FROM scholarship WHERE status != 'Archived' ORDER BY deadline DESC")
                programs = cur.fetchall()
                
                # 3. Expiry Logic: Compare current date with database deadline
                today = datetime.now().date()
                
                for prog in programs:
                    if prog['deadline']:
                        # Ensure we compare date objects to date objects
                        deadline = prog['deadline']
                        if isinstance(deadline, datetime):
                            deadline = deadline.date()
                        
                        # Adds a flag to the program dict for frontend warning labels
                        prog['is_expired'] = today > deadline
                        
            # 4. Render with admin_name for the top bar
            return render_template('scholarship_manager.html', 
                                   admin_name=session['full_name'], 
                                   scholarships=programs)
        finally:
            connection.close()
            
    # If not logged in as admin, redirect to login page
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
                # Modified SQL: Added "AND a.reviewerID IS NULL"
                sql_apps = """
                    SELECT a.applicationID, u.fullName, u.userID, s.scholarshipName 
                    FROM application a
                    JOIN user u ON a.studentID = u.userID
                    JOIN scholarship s ON a.scholarshipID = s.scholarshipID
                    WHERE s.status != 'Archived' 
                    AND a.applicationStatus = 'Submitted'
                    AND a.reviewerID IS NULL
                """
                cur.execute(sql_apps)
                assignments = cur.fetchall()

                # Fetch real Reviewers and calculate their workload
                sql_revs = """
                    SELECT u.userID, u.fullName, 
                    (SELECT COUNT(*) FROM application WHERE reviewerID = u.userID) as current_load
                    FROM user u 
                    WHERE u.role = 'reviewer' AND u.status != 'Inactive'
                """
                cur.execute(sql_revs)
                reviewers_list = cur.fetchall()

            return render_template('reviewer_assignment.html', 
                                   admin_name=session['full_name'], 
                                   pending_tasks=assignments,
                                   reviewers=reviewers_list)
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/assign_reviewers_submit', methods=['POST'])
def assign_reviewers_submit():
    if 'user_id' in session and session.get('role') == 'admin':
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                # Loop through all form data to find reviewer selections
                for key, reviewer_id in request.form.items():
                    if key.startswith('reviewer_') and reviewer_id:
                        # Extract the applicationID from the input name
                        app_id = key.replace('reviewer_', '')
                        
                        # Update the database with the assigned reviewer
                        sql = "UPDATE application SET reviewerID = %s WHERE applicationID = %s"
                        cur.execute(sql, (reviewer_id, app_id))
            
            connection.commit()
            # Storing message for the Toast Alert
            flash("Reviewer assignments confirmed and workloads updated.")
            return redirect(url_for('reviewer_assignment'))
        except Exception as e:
            if connection: connection.rollback()
            return f"Error: {e}"
        finally:
            if connection: connection.close()
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
        uID = session['user_id']
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                # Fetch applications assigned to THIS reviewer that haven't been scored yet
                sql = """SELECT a.applicationID, u.fullName, u.userID, s.faculty, a.applicationStatus 
                         FROM application a
                         JOIN user u ON a.studentID = u.userID
                         JOIN scholarship s ON a.scholarshipID = s.scholarshipID
                         WHERE a.reviewerID = %s AND a.score IS NULL"""
                cur.execute(sql, (uID,))
                pending_list = cur.fetchall()
                
                # Fetch counts for the dashboard cards
                cur.execute("SELECT COUNT(*) as total FROM application WHERE reviewerID = %s", (uID,))
                total_assigned = cur.fetchone()['total']
                
                cur.execute("SELECT COUNT(*) as completed FROM application WHERE reviewerID = %s AND score IS NOT NULL", (uID,))
                completed_count = cur.fetchone()['completed']

            return render_template('reviewer_queue.html', 
                                   reviewer_name=session['full_name'], 
                                   pending_tasks=pending_list,
                                   total=total_assigned,
                                   done=completed_count,
                                   remain=len(pending_list))
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/reviewer/assessment/<app_id>')
def reviewer_assessment(app_id):
    if 'user_id' in session and session.get('role') == 'reviewer':
        # Store ID in session so the sidebar link works across pages
        session['current_assessment_id'] = app_id
        
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                sql = """SELECT a.*, u.fullName, u.userID, s.faculty, s.cgpa
                         FROM application a
                         JOIN user u ON a.studentID = u.userID
                         JOIN student s ON a.studentID = s.studentID
                         WHERE a.applicationID = %s"""
                cur.execute(sql, (app_id,))
                application_data = cur.fetchone()

            if not application_data:
                session.pop('current_assessment_id', None)
                return redirect(url_for('reviewer_queue'))

            return render_template('reviewer_assessment.html', 
                                   reviewer_name=session['full_name'], 
                                   app=application_data)
        finally:
            connection.close()
    return redirect(url_for('index'))

# --- Unified Submit Assessment Route ---
@app.route('/submit_assessment', methods=['POST'])
def submit_assessment():
    if 'user_id' in session and session.get('role') == 'reviewer':
        app_id = request.form.get('applicationID')
        score = request.form.get('totalScore')
        feedback = request.form.get('feedback')
        recommendation = request.form.get('recommendation')
        
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                # 1. Update the application with scores and recommendation
                sql = """UPDATE application 
                         SET score = %s, 
                             applicationStatus = %s, 
                             reviewDate = %s 
                         WHERE applicationID = %s"""
                cur.execute(sql, (score, recommendation, datetime.now(), app_id))
            
            connection.commit()
            
            # 2. Cleanup session memory for sidebar logic
            session.pop('current_assessment_id', None)
            
            # 3. Flash message for the redirect page
            flash("Assessment Finalized Successfully")
            return redirect(url_for('reviewer_queue'))
        except Exception as e:
            if connection: connection.rollback()
            return f"Error: {e}"
        finally:
            if connection: connection.close()
            
    return redirect(url_for('index'))

@app.route('/scoring_history')
def scoring_history():
    if 'user_id' in session and session.get('role') == 'reviewer':
        uID = session['user_id']
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                # Fetch only COMPLETED assessments for this reviewer
                sql = """SELECT a.applicationID, u.fullName, u.userID, a.score, 
                                a.applicationStatus, a.reviewDate 
                         FROM application a
                         JOIN user u ON a.studentID = u.userID
                         WHERE a.reviewerID = %s AND a.score IS NOT NULL
                         ORDER BY a.reviewDate DESC"""
                cur.execute(sql, (uID,))
                history_list = cur.fetchall()

            return render_template('scoring_history.html', 
                                   reviewer_name=session['full_name'], 
                                   history=history_list)
        finally:
            connection.close()
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
    # CHANGE THIS LINE: Add 'admin' to the allowed roles
    if 'user_id' in session and session.get('role') in ['admin', 'committee']:
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
        
        # Pass the correct name variable based on the role
        display_name = session.get('full_name')
        return render_template('committee_manager.html', 
                               admin_name=display_name, 
                               committee_name=display_name, 
                               sch=scholarship_data)
                               
    # If role is not admin or committee, redirect to login
    return redirect(url_for('index'))

@app.route('/add_scholarship_submit', methods=['POST'])
def add_scholarship_submit():
    if 'user_id' in session and session.get('role') in ['admin', 'committee']:
        user_role = session.get('role')
        form_action = request.form.get('action')
        status = 'Published' if form_action == 'publish' else 'Draft'
        
        # Check if we are updating an existing record
        existing_id = request.form.get('scholarshipID')

        # FIX: Define the variables by capturing them from the form
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
                    # INSERT new record with sequential ID
                    sch_id = generate_sequential_id('SCH', 'scholarship', 'scholarshipID')
                    sql = """INSERT INTO scholarship 
                             (scholarshipID, scholarshipName, scholarshipCriteria, 
                              deadline, scholarshipAmount, termAndCondition, 
                              faculty, totalSlots, description, status) 
                             VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
                    cur.execute(sql, (sch_id, name, criteria, deadline, amount, 
                                      terms, faculty, slots, description, status))
                
            connection.commit()
            flash(f"Scholarship '{name}' saved successfully.")

            # Redirect based on role
            if user_role == 'admin':
                return redirect(url_for('scholarship_manager'))
            else:
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
    if 'user_id' in session:
        uID = session['user_id']
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                # Keep your existing dashboard query...
                sql = """SELECT a.*, s.scholarshipName 
                         FROM application a 
                         JOIN scholarship s ON a.scholarshipID = s.scholarshipID 
                         WHERE a.studentID = %s AND a.applicationStatus != 'Draft'
                         ORDER BY a.submissionDate DESC"""
                cur.execute(sql, (uID,))
                active_apps = cur.fetchall()
                
                # --- ADD THIS FOR THE BELL ---
                sql_notif = """SELECT a.*, s.scholarshipName 
                               FROM application a 
                               JOIN scholarship s ON a.scholarshipID = s.scholarshipID 
                               WHERE a.studentID = %s"""
                cur.execute(sql_notif, (uID,))
                user_apps = cur.fetchall()
                
            return render_template('student_dashboard.html', 
                                   user_id=uID, 
                                   name=session.get('full_name'),
                                   applications=user_apps, # Used by the bell
                                   dashboard_apps=active_apps, # Used by the cards
                                   app_count=len(active_apps))
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/scholarship_detail/<sch_id>')
def scholarship_detail(sch_id):
    # 1. Permission Check: Allow both Students and Admins
    if 'user_id' in session and session.get('role') in ['student', 'admin']:
        uID = session['user_id']
        role = session.get('role')
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                # 2. Fetch scholarship data (Common for both roles)
                cur.execute("SELECT * FROM scholarship WHERE scholarshipID = %s", (sch_id,))
                scholarship_data = cur.fetchone()
                
                if not scholarship_data:
                    return redirect(url_for('scholarship_discovery'))

                # 3. Role-Specific Logic
                student_data = None
                app_check = None
                user_apps = []

                if role == 'student':
                    # Fetch student profile data
                    cur.execute("SELECT * FROM student WHERE studentID = %s", (uID,))
                    student_data = cur.fetchone()

                    # Check for existing application
                    cur.execute("SELECT applicationStatus FROM application WHERE studentID = %s AND scholarshipID = %s", (uID, sch_id))
                    app_check = cur.fetchone()
                    
                    # Fetch data for the student's notification bell
                    sql_notif = """SELECT a.*, s.scholarshipName 
                                   FROM application a 
                                   JOIN scholarship s ON a.scholarshipID = s.scholarshipID 
                                   WHERE a.studentID = %s"""
                    cur.execute(sql_notif, (uID,))
                    user_apps = cur.fetchall()

                # 4. Render Template
                # Pass admin_name or committee_name for sidebar compatibility if needed
                return render_template('scholarship_detail.html', 
                                       user_id=uID, 
                                       role=role,
                                       name=session.get('full_name'),
                                       admin_name=session.get('full_name'), # For Admin Sidebar
                                       student=student_data,
                                       sch=scholarship_data,
                                       applications=user_apps,
                                       existing_status=app_check['applicationStatus'] if app_check else None)
        finally:
            connection.close()
            
    return redirect(url_for('index'))

@app.route('/tracking_hub')
def tracking_hub():
    if 'user_id' in session:
        uID = session['user_id']
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                # 1. Fetch all applications for this student
                sql = """SELECT a.*, s.scholarshipName 
                         FROM application a 
                         JOIN scholarship s ON a.scholarshipID = s.scholarshipID 
                         WHERE a.studentID = %s 
                         ORDER BY a.submissionDate DESC"""
                cur.execute(sql, (uID,))
                user_apps = cur.fetchall()

                # 2. Dynamic Counters
                # Count 'Active' (Submitted/In Review)
                active_count = sum(1 for a in user_apps if a['applicationStatus'] in ['Submitted', 'In Review'])
                # Count 'Drafts'
                draft_count = sum(1 for a in user_apps if a['applicationStatus'] == 'Draft')
                # Count 'Completed' (Awarded/Rejected)
                completed_count = sum(1 for a in user_apps if a['applicationStatus'] in ['Awarded', 'Rejected'])

            return render_template('tracking_hub.html', 
                                   user_id=uID, 
                                   name=session.get('full_name'), 
                                   applications=user_apps,
                                   active_c=active_count,
                                   draft_c=draft_count,
                                   completed_c=completed_count)
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/profile') 
def profile():
    if 'user_id' in session:
        uID = session['user_id']
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                sql = "SELECT * FROM user JOIN student ON user.userID = student.studentID WHERE user.userID = %s"
                cur.execute(sql, (uID,))
                student_data = cur.fetchone()

                # --- ADD THIS FOR THE BELL ---
                sql_notif = """SELECT a.*, s.scholarshipName 
                            FROM application a 
                            JOIN scholarship s ON a.scholarshipID = s.scholarshipID 
                            WHERE a.studentID = %s"""
                cur.execute(sql_notif, (session['user_id'],))
                user_apps = cur.fetchall()
                
                return render_template('profile.html', 
                                       user_id=uID, 
                                       name=session.get('full_name'),
                                       student=student_data,
                                       applications=user_apps) # Pass to sync bell
        finally:
            connection.close()
    return redirect(url_for('index'))

# New Route to save changes to the database
@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    # Collect data from the form
    uID = session['user_id']
    fullName = request.form.get('fullName')
    email = request.form.get('email')
    phone = request.form.get('phone')
    faculty = request.form.get('faculty')
    course = request.form.get('course')
    cgpa = request.form.get('cgpa')
    credits = request.form.get('credits')

    connection = get_db_connection()
    try:
        with connection.cursor() as cur:
            # Update user table
            cur.execute("UPDATE user SET fullName=%s, email=%s, phone=%s WHERE userID=%s", 
                        (fullName, email, phone, uID))
            # Update student table
            cur.execute("UPDATE student SET faculty=%s, course=%s, cgpa=%s, total_credits=%s WHERE studentID=%s", 
                        (faculty, course, cgpa, credits, uID))
        
        connection.commit()
        session['full_name'] = fullName # Sync session with new name
        return redirect(url_for('profile'))
    except Exception as e:
        connection.rollback()
        return f"Database Error: {e}"
    finally:
        connection.close()

@app.route('/application_form')
def application_form():
    if 'user_id' in session and session.get('role') == 'student':
        uID = session['user_id']
        schID = request.args.get('id')
        
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                # 1. SECURITY CHECK: Does an application (that isn't rejected) already exist?
                # This prevents duplicate 'Submitted' or 'In Review' applications.
                cur.execute("""SELECT applicationStatus FROM application 
                               WHERE studentID = %s AND scholarshipID = %s 
                               AND applicationStatus != 'Rejected'""", (uID, schID))
                existing_app = cur.fetchone()

                # If they have an active application that IS NOT a draft, block access
                if existing_app and existing_app['applicationStatus'] != 'Draft':
                    flash("Access Denied: You already have an active application for this scholarship.")
                    return redirect(url_for('tracking_hub'))

                # 2. Load standard student profile data
                cur.execute("SELECT u.fullName, s.cgpa, s.faculty FROM user u JOIN student s ON u.userID = s.studentID WHERE u.userID = %s", (uID,))
                student_data = cur.fetchone()

                # 3. Check for a saved Draft to pre-fill the form
                cur.execute("SELECT * FROM application WHERE studentID = %s AND scholarshipID = %s AND applicationStatus = 'Draft'", (uID, schID))
                existing_draft = cur.fetchone()
                
                # 4. Get scholarship name for the form header
                cur.execute("SELECT scholarshipName FROM scholarship WHERE scholarshipID = %s", (schID,))
                sch_info = cur.fetchone()

                return render_template('application_form.html', 
                                       student=student_data, 
                                       user_id=uID, 
                                       draft=existing_draft, 
                                       sch=sch_info)

        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/scholarship_discovery')
def scholarship_discovery():
    if 'user_id' in session and session.get('role') == 'student':
        # 1. Get ALL filters from URL
        selected_faculty = request.args.get('faculty', 'All')
        selected_cgpa = request.args.get('cgpa', '0.0')
        selected_category = request.args.get('category', 'All')

        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                # 2. Base query
                sql = "SELECT * FROM scholarship WHERE status = 'Published'"
                params = []

                # 3. Apply Category Filter
                if selected_category != 'All':
                    sql += " AND (scholarshipCriteria LIKE %s OR scholarshipName LIKE %s)"
                    params.extend([f"%{selected_category}%", f"%{selected_category}%"])

                # 4. Apply Advanced Faculty Keyword Matching
                if selected_faculty != 'All':
                    faculty_map = {
                        'FCI': ['Computing', 'Information', 'Technology','FCI', 'All'],
                        'FCM': ['Multimedia', 'Creative', 'Media', 'FCM', 'All'], # Added 'FCM' as a keyword
                        'FOB': ['Business', 'Accounting', 'Finance', 'Management', 'FOB', 'All'],
                        'FIST': ['Information', 'Science', 'Artificial Intelligence', 'FIST', 'All'],
                        'FOE': ['Engineering', 'Electrical', 'Mechanical', 'Civil', 'FOE', 'All'],
                        'FCA': ['Cinematic', 'Art', 'Animation', 'FCA', 'All']
                    }
                    keywords = faculty_map.get(selected_faculty, [selected_faculty])
                    
                    # This logic searches for any of the keywords OR "All Faculties"
                    keyword_placeholders = " OR ".join(["faculty LIKE %s"] * len(keywords))
                    sql += f" AND ({keyword_placeholders} OR faculty LIKE %s)"
                    
                    for k in keywords:
                        params.append(f"%{k}%")
                    params.append("%All%")
                    
                
                # 5. Execute with the correct parameter count
                cur.execute(sql, tuple(params))
                published_list = cur.fetchall()

                sql_notif = """SELECT a.*, s.scholarshipName 
                            FROM application a 
                            JOIN scholarship s ON a.scholarshipID = s.scholarshipID 
                            WHERE a.studentID = %s"""
                cur.execute(sql_notif, (session['user_id'],))
                user_apps = cur.fetchall()
                
            return render_template('scholarship_discovery.html', 
                                   scholarships=published_list,
                                   user_id=session.get('user_id'), 
                                   name=session.get('full_name'),
                                   sel_faculty=selected_faculty,
                                   sel_cgpa=selected_cgpa,
                                   sel_category=selected_category,
                                   applications=user_apps)
        
        finally:
            connection.close()
            
    return redirect(url_for('index'))

@app.route('/submit_application', methods=['POST'])
def submit_application():
    # ... code to save form data to MySQL 'application' table ...
    flash("Application submitted successfully!")
    # Redirect to Tracking Hub after success
    return redirect(url_for('tracking_hub'))

@app.route('/submit_application_data', methods=['POST'])
def submit_application_data():
    if 'user_id' in session:
        uID = session['user_id']
        data = request.form
        schID = data.get('scholarshipID')
        
        # Determine Bank Name
        bank_choice = data.get('bank')
        other_name = data.get('other_bank_name')
        final_bank_name = other_name if bank_choice == 'Others' else bank_choice

        # Collect fields
        phone, semester = data.get('phone'), data.get('semester')
        activities, income = data.get('activities'), data.get('income')
        guardian_job, statement, bank_acc = data.get('guardianJob'), data.get('statement'), data.get('accNo')
        
        # File handling
        file1 = request.files.get('transcript')
        filename1 = ""
        if file1 and file1.filename != '':
            filename1 = secure_filename(f"{uID}_{schID}_transcript.pdf")
            file1.save(os.path.join(app.config['UPLOAD_FOLDER'], filename1))

        file2 = request.files.get('income_proof')
        filename2 = ""
        if file2 and file2.filename != '':
            filename2 = secure_filename(f"{uID}_{schID}_income_proof.pdf")
            file2.save(os.path.join(app.config['UPLOAD_FOLDER'], filename2))

        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                cur.execute("SELECT applicationID FROM application WHERE studentID=%s AND scholarshipID=%s", (uID, schID))
                existing = cur.fetchone()

                if existing:
                    sql = """UPDATE application SET 
                             submissionDate=%s, applicationStatus='Submitted', phone=%s, 
                             semester=%s, leadershipActivities=%s, householdIncome=%s, 
                             guardianOccupation=%s, statementOfPurpose=%s, bankAccNo=%s, 
                             bank=%s, documentUploaded=%s, incomeProof=%s WHERE applicationID=%s"""
                    cur.execute(sql, (datetime.now(), phone, semester, activities, income, 
                                      guardian_job, statement, bank_acc, final_bank_name, filename1, filename2, existing['applicationID']))
                else:
                    app_id = str(uuid.uuid4())[:8]
                    sql = """INSERT INTO application 
                             (applicationID, submissionDate, applicationStatus, studentID, scholarshipID, 
                              phone, semester, leadershipActivities, householdIncome, 
                              guardianOccupation, statementOfPurpose, bankAccNo, bank, documentUploaded, incomeProof)
                             VALUES,  (%s, %s, 'Submitted', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
                    cur.execute(sql, (app_id, datetime.now(), uID, schID, phone, semester, 
                                      activities, income, guardian_job, statement, bank_acc, final_bank_name, filename1, filename2, existing['applicationID']))
            connection.commit()
            return redirect(url_for('tracking_hub'))
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/save_draft', methods=['POST'])
def save_draft():
    if 'user_id' in session:
        # Collect whatever data the student has filled so far
        data = request.form
        uID = session['user_id']
        schID = data.get('scholarshipID')
        
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                # Check if a draft already exists to update it, or insert new
                app_id = str(uuid.uuid4())[:8]
                sql = """INSERT INTO application 
                         (applicationID, studentID, scholarshipID, applicationStatus, submissionDate) 
                         VALUES (%s, %s, %s, 'Draft', %s) 
                         ON DUPLICATE KEY UPDATE submissionDate=%s"""
                cur.execute(sql, (app_id, uID, schID, datetime.now(), datetime.now()))
            connection.commit()
            return redirect(url_for('tracking_hub'))
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/save_application_draft', methods=['POST'])
def save_application_draft():
    if 'user_id' in session:
        uID = session['user_id']
        data = request.form
        schID = data.get('scholarshipID')
        
        # Determine Bank Name: Dropdown or Specify Box?
        bank_choice = request.form.get('bank')
        other_name = request.form.get('other_bank_name')
        final_bank_name = other_name if bank_choice == 'Others' else bank_choice

        # Capture other fields
        phone = data.get('phone')
        semester = data.get('semester')
        activities = data.get('activities')
        statement = data.get('statement')
        income = data.get('income') or 0
        guardian_job = data.get('guardianJob')
        bank_acc = data.get('accNo')
        

        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                cur.execute("SELECT applicationID FROM application WHERE studentID=%s AND scholarshipID=%s AND applicationStatus='Draft'", (uID, schID))
                existing = cur.fetchone()

                if existing:
                    sql = """UPDATE application SET 
                                submissionDate=%s, phone=%s, semester=%s, leadershipActivities=%s, 
                                statementOfPurpose=%s, householdIncome=%s, guardianOccupation=%s, 
                                bankAccNo=%s, bank=%s WHERE applicationID=%s"""
                    cur.execute(sql, (datetime.now(), phone, semester, activities, statement, 
                      income, guardian_job, bank_acc, final_bank_name, existing['applicationID']))
                else:
                    app_id = str(uuid.uuid4())[:8]
                    sql = """INSERT INTO application 
                             (applicationID, submissionDate, applicationStatus, studentID, scholarshipID, 
                              phone, semester, leadershipActivities, statementOfPurpose, householdIncome, 
                              guardianOccupation, bankAccNo, bank) 
                             VALUES (%s, %s, 'Draft', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
                    cur.execute(sql, (app_id, datetime.now(), uID, schID, phone, semester, activities, statement, income, guardian_job, bank_acc, final_bank_name))
            
            connection.commit()
            return redirect(url_for('tracking_hub'))
        finally:
            connection.close()
    return redirect(url_for('index'))


@app.route('/delete_draft/<app_id>', methods=['POST'])
def delete_draft(app_id):
    if 'user_id' in session:
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                # Security: Only delete if it belongs to this student and is a Draft
                sql = "DELETE FROM application WHERE applicationID = %s AND studentID = %s AND applicationStatus = 'Draft'"
                cur.execute(sql, (app_id, session['user_id']))
            connection.commit()            
            
        except Exception as e:
            return f"Error: {e}"
        finally:
            connection.close()
    return redirect(url_for('tracking_hub'))

def generate_sequential_id(prefix, table_name, column_name):
    connection = get_db_connection()
    try:
        with connection.cursor() as cur:
            cur.execute(f"SELECT {column_name} FROM {table_name} ORDER BY {column_name} DESC LIMIT 1")
            last_record = cur.fetchone()
            
            if not last_record:
                return f"{prefix}0001"
            
            last_id = last_record[column_name]
            last_num = int(last_id.replace(prefix, ""))
            new_num = last_num + 1
            return f"{prefix}{new_num:04d}" 
    finally:
        connection.close()

if __name__ == '__main__':
    app.run(debug=True)