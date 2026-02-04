# 1. Standard Python library imports (Built-in)
import io  # MUST be on its own line
import os
import uuid
from datetime import datetime

# 2. Flask specific imports
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file

# 3. Third-party library imports (Installed via pip)
import pymysql.cursors
from werkzeug.utils import secure_filename

# 4. ReportLab imports
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.secret_key = 'super_secret_key_123'

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
            # We fetch the user by ID
            cur.execute("SELECT * FROM user WHERE userID = %s", (uid,))
            user = cur.fetchone()
    finally:
        connection.close()

    # CRITICAL CHANGE: Added check for user['status'] == 'Active'
    if user and user['password'] == pwd:
        if user['status'] == 'Active':
            session['user_id'] = user['userID']
            session['full_name'] = user['fullName']
            session['role'] = user['role']
            
            log_security_event(uid, f"{user['role'].capitalize()} logged in successfully.")

            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'reviewer':
                return redirect(url_for('reviewer_dashboard'))
            elif user['role'] == 'committee':
                return redirect(url_for('committee_overview'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            # If the user exists but is Inactive
            flash("Your account has been deactivated. Please contact the administrator.")
            return redirect(url_for('index'))
    else:
        # If the password is wrong or user doesn't exist
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
    connection = get_db_connection() #
    try:
        with connection.cursor() as cur:
            # 1. Insert into the main user table
            # FIXED: Includes phone and gender from the registration form
            sql_user = """INSERT INTO user (userID, fullName, password, email, phone, gender, role, status) 
                          VALUES (%s, %s, %s, %s, %s, %s, 'student', 'Active')"""
            cur.execute(sql_user, (
                data['studentID'], 
                data['fullName'], 
                data['password'], 
                data['email'], 
                data.get('phone'), 
                data.get('gender')
            ))
            
            # 2. Insert detailed academic profile into student table
            sql_student = """INSERT INTO student (studentID, faculty, course, address, dob) 
                             VALUES (%s, %s, %s, %s, %s)"""
            cur.execute(sql_student, (
                data['studentID'], 
                data['faculty'], 
                data['course'], 
                data['address'], 
                data['dob']
            ))
            
            # 3. Initialize the student's dashboard metrics
            # Set all starting application counts to 0
            sql_dash = """INSERT INTO DASHBOARD (userID, totalApplications, acceptedApplications, rejectedApplications, pendingApplications) 
                          VALUES (%s, 0, 0, 0, 0)"""
            cur.execute(sql_dash, (data['studentID'],))

        # IMPORTANT: Commit only after ALL three inserts are successful
        connection.commit()
        
        # Log the security event for the new registration
        log_security_event(data['studentID'], "New student account registered.")
        
        flash("Registration successful!")
        return redirect(url_for('index'))

    except Exception as e:
        # If ANY table fails, undo everything so the email/ID is available to try again
        if connection: 
            connection.rollback()
        return f"Database Error: {e}"
    finally:
        if connection: 
            connection.close() #

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
        data = get_dashboard_stats() # Call dynamic data helper
        return render_template('admin_dashboard.html', 
                               admin_name=session['full_name'], 
                               user_role='admin',
                               **data) # Expands the stats, trends, and distribution dictionaries
    return redirect(url_for('index'))

@app.route('/user_management')
def user_management():
    if 'user_id' in session and session.get('role') == 'admin':
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                cur.execute("SELECT userID, fullName, email, role FROM user WHERE status != 'Inactive'")
                users_list = cur.fetchall()
            return render_template('user_management.html', admin_name=session.get('full_name'), users=users_list)
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
        # Capture variables from the specialized single-column form
        uid = request.form.get('userid')
        name = request.form.get('fullname')
        email = request.form.get('email')
        temp_pwd = request.form.get('temp_password') # New field from design
        role = request.form.get('role')
        
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                # Insert into USER table as an active internal staff member
                sql = """INSERT INTO user (userID, role, fullName, password, email, status) 
                         VALUES (%s, %s, %s, %s, %s, 'Active')"""
                cur.execute(sql, (uid, role, name, temp_pwd, email))
            
            connection.commit()
            log_security_event(session['user_id'], f"Admin onboarded new {role}: {name} ({uid})")
            
            flash(f"Successfully created {role} account for {name}.")
            return redirect(url_for('user_management'))
            
        except Exception as e:
            if connection: connection.rollback()
            return f"Error: {e}"
        finally:
            if connection: connection.close()
    return redirect(url_for('index'))

@app.route('/edit_user/<userid>')
def edit_user(userid):
    if 'user_id' in session and session.get('role') == 'admin':
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                cur.execute("SELECT * FROM user WHERE userID = %s", (userid,))
                user_data = cur.fetchone()
            if user_data:
                return render_template('edit_user.html', user=user_data, admin_name=session.get('full_name'))
            flash("User not found.")
            return redirect(url_for('user_management'))
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/reset_password_request', methods=['POST'])
def reset_password_request():
    # Capture email from the hidden input
    email = request.form.get('email')
    
    if not email:
        flash("Error: No email provided.")
        return redirect(url_for('user_management'))

    connection = get_db_connection()
    try:
        with connection.cursor() as cur:
            # 1. Strict verification: Get the ID and Name
            cur.execute("SELECT userID, fullName FROM user WHERE email = %s", (email,))
            user_record = cur.fetchone()
            
            # CRITICAL CHECK: Only proceed if the user actually exists
            if user_record and user_record['userID']:
                uID = user_record['userID']
                
                # 2. Log the Security Event (Shows in Admin Logs)
                log_security_event(uID, f"Admin initiated password reset for {email}")

                # 3. Insert into NOTIFICATION table (This is the "Saving" part)
                notif_id = str(uuid.uuid4())[:8]
                msg = f"Security Alert: A password reset link was sent to your email ({email})."
                
                # We use 'System Alert' type to match your tracking_hub filters
                sql_notif = """INSERT INTO NOTIFICATION (notificationID, userID, message, status, timestamp, type) 
                               VALUES (%s, %s, %s, 'Unread', %s, 'System Alert')"""
                
                cur.execute(sql_notif, (notif_id, uID, msg, datetime.now()))
                
                # COMMIT makes the changes permanent in the DB
                connection.commit()
                flash(f"Reset link successfully sent to {email}")
            else:
                flash(f"Error: User with email {email} does not exist in the database.")
                
    except Exception as e:
        if connection: connection.rollback()
        # Log the actual error to your terminal for debugging
        print(f"DEBUG ERROR: {e}")
        return f"Backend Error: {e}"
    finally:
        if connection: connection.close()
        
    return redirect(request.referrer or url_for('user_management'))

@app.route('/delete_user/<userid>', methods=['POST'])
def delete_user(userid):
    if 'user_id' in session and session.get('role') == 'admin':
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
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
                # LIVE DATA SQL: Subtracts 'Awarded' applications from totalSlots
                sql = """
                    SELECT s.*, 
                    (s.totalSlots - (SELECT COUNT(*) FROM application WHERE scholarshipID = s.scholarshipID AND applicationStatus = 'Awarded')) as slotsLeft
                    FROM scholarship s
                    WHERE s.status != 'Archived'
                    ORDER BY s.deadline DESC
                """
                cur.execute(sql)
                programs = cur.fetchall()
                
                today = datetime.now().date()
                for prog in programs:
                    if prog['deadline']:
                        deadline = prog['deadline']
                        if isinstance(deadline, datetime):
                            deadline = deadline.date()
                        prog['is_expired'] = today > deadline
                        
            return render_template('scholarship_manager.html', admin_name=session['full_name'], scholarships=programs)
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/admin_manage_status/<sch_id>/<action>', methods=['POST'])
def admin_manage_status(sch_id, action):
    if 'user_id' in session and session.get('role') == 'admin':
        new_status = 'Closed' if action == 'close' else 'Archived'
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                cur.execute("UPDATE scholarship SET status = %s WHERE scholarshipID = %s", (new_status, sch_id))
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
                # FIXED: Added s.faculty for future filtering
                sql_apps = """
                    SELECT a.applicationID, u.fullName, u.userID, s.scholarshipName, s.faculty 
                    FROM application a
                    JOIN user u ON a.studentID = u.userID
                    JOIN scholarship s ON a.scholarshipID = s.scholarshipID
                    WHERE s.status != 'Archived' 
                    AND a.applicationStatus = 'Submitted'
                    AND a.reviewerID IS NULL
                """
                cur.execute(sql_apps)
                assignments = cur.fetchall()

                # LOAD CALCULATION: Only counts active (unscored) tasks
                sql_revs = """
                    SELECT u.userID, u.fullName, 
                    (SELECT COUNT(*) FROM application WHERE reviewerID = u.userID AND score IS NULL) as current_load
                    FROM user u 
                    WHERE u.role = 'reviewer' AND u.status != 'Inactive'
                """
                cur.execute(sql_revs)
                reviewers_list = cur.fetchall()
            return render_template('reviewer_assignment.html', admin_name=session['full_name'], pending_tasks=assignments, reviewers=reviewers_list)
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/assign_reviewers_submit', methods=['POST'])
def assign_reviewers_submit():
    if 'user_id' in session and session.get('role') == 'admin':
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                for key, reviewer_id in request.form.items():
                    if key.startswith('reviewer_') and reviewer_id:
                        app_id = key.replace('reviewer_', '')
                        
                        # LOGIC: Change status to 'Under Review' upon assignment
                        sql = "UPDATE application SET reviewerID = %s, applicationStatus = 'Under Review' WHERE applicationID = %s"
                        cur.execute(sql, (reviewer_id, app_id))

                        # NEW: Get info for the notification
                        cur.execute("""SELECT studentID, scholarshipName FROM application a 
                                       JOIN scholarship s ON a.scholarshipID = s.scholarshipID 
                                       WHERE applicationID = %s""", (app_id,))
                        task = cur.fetchone()

                        if task:
                            # Create Notification for Assignment
                            notif_id = str(uuid.uuid4())[:8]
                            msg = f"Reviewer assigned for {task['scholarshipName']} - Pending Review."
                            cur.execute("""INSERT INTO NOTIFICATION (notificationID, userID, message, status, timestamp, type) 
                                           VALUES (%s, %s, %s, 'Unread', %s, 'System Alert')""", 
                                        (notif_id, task['studentID'], msg, datetime.now()))

            connection.commit()
            flash("Reviewer assigned. Application is now Under Review.")
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
        data = get_dashboard_stats() # Call dynamic data helper
        return render_template('reviewer_dashboard.html', 
                               reviewer_name=session['full_name'],
                               user_role='reviewer',
                               **data)
    return redirect(url_for('index'))

@app.route('/reviewer_queue')
def reviewer_queue():
    if 'user_id' in session and session.get('role') == 'reviewer':
        uID = session['user_id']
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                sql = """SELECT a.applicationID, u.fullName, u.userID, s.faculty, a.applicationStatus 
                         FROM application a
                         JOIN user u ON a.studentID = u.userID
                         JOIN scholarship s ON a.scholarshipID = s.scholarshipID
                         WHERE a.reviewerID = %s AND a.score IS NULL""" 
                cur.execute(sql, (uID,))
                pending_list = cur.fetchall()

                # 
                cur.execute("SELECT COUNT(*) as total FROM application WHERE reviewerID = %s", (uID,))
                total_assigned = cur.fetchone()['total']
                cur.execute("SELECT COUNT(*) as completed FROM application WHERE reviewerID = %s AND score IS NOT NULL", (uID,))
                completed_count = cur.fetchone()['completed']

            return render_template('reviewer_queue.html', reviewer_name=session['full_name'], 
                                   pending_tasks=pending_list, total=total_assigned, 
                                   done=completed_count, remain=len(pending_list))
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/reviewer/assessment/<app_id>')
def reviewer_assessment(app_id):
    if 'user_id' in session and session.get('role') == 'reviewer':
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
            return render_template('reviewer_assessment.html', reviewer_name=session['full_name'], app=application_data)
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/submit_assessment', methods=['POST'])
def submit_assessment():
    if 'user_id' in session and session.get('role') == 'reviewer':
        reviewer_id = session['user_id']
        app_id = request.form.get('applicationID')
        score = request.form.get('totalScore')
        feedback = request.form.get('feedback')
        
        # 1. Capture the direct recommendation ("Approved" or "Rejected")
        recommendation = request.form.get('recommendation') 
        new_status = recommendation 
        
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                # 2. Update application table
                sql_app = """UPDATE application 
                             SET score = %s, applicationStatus = %s, reviewDate = %s 
                             WHERE applicationID = %s"""
                cur.execute(sql_app, (score, new_status, datetime.now(), app_id))
                
                # 3. Insert into detailed REVIEW record
                rev_id = str(uuid.uuid4())[:8]
                sql_rev = """INSERT INTO REVIEW (reviewID, applicationID, reviewerID, score, feedbackComment, reviewDate, stage) 
                             VALUES (%s, %s, %s, %s, %s, %s, %s)"""
                cur.execute(sql_rev, (rev_id, app_id, reviewer_id, score, feedback, datetime.now(), 'Evaluation Phase'))

                # 4. Fetch info for Notification and Dashboard Update
                cur.execute("SELECT studentID, scholarshipName FROM application a JOIN scholarship s ON a.scholarshipID = s.scholarshipID WHERE applicationID = %s", (app_id,))
                app_info = cur.fetchone()
                student_id = app_info['studentID']
                sch_name = app_info['scholarshipName']

                # 5. FIX: Strict conditional for the message
                if new_status == 'Approved':
                    msg = f"Congratulations! Your application for {sch_name} has been approved by our Reviewer. Waiting for Interview Scheduling."
                    notif_type = 'Review Update'
                else:
                    # REJECTED PATH: Update Dashboard Statistics correctly
                    msg = f"Application Update: We regret to inform you that your application for {sch_name} was not approved."
                    notif_type = 'System Alert'
                    
                    # FIX: Ensure rejected count goes up and pending goes down
                    sql_dash = """UPDATE DASHBOARD 
                                SET rejectedApplications = rejectedApplications + 1, 
                                pendingApplications = pendingApplications - 1 
                                WHERE userID = %s"""
                    cur.execute(sql_dash, (student_id,))

                notif_id = str(uuid.uuid4())[:8]
                cur.execute("""INSERT INTO NOTIFICATION (notificationID, userID, message, status, timestamp, type) 
                               VALUES (%s, %s, %s, 'Unread', %s, %s)""", 
                            (notif_id, student_id, msg, datetime.now(), notif_type))

            connection.commit()
            session.pop('current_assessment_id', None)
            flash(f"Assessment complete. Status is now {new_status}.")
            return redirect(url_for('reviewer_queue'))
            
        except Exception as e:
            if connection: connection.rollback()
            return f"Error: {e}"
        finally:
            if connection: connection.close()
            
    return redirect(url_for('index'))

@app.route('/view_assessment_summary/<app_id>')
def view_assessment_summary(app_id):
    if 'user_id' in session and session.get('role') == 'reviewer':
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                sql = """SELECT a.*, r.feedbackComment, r.reviewDate, u.fullName, u.userID
                         FROM application a
                         JOIN user u ON a.studentID = u.userID
                         JOIN REVIEW r ON a.applicationID = r.applicationID
                         WHERE a.applicationID = %s"""
                cur.execute(sql, (app_id,))
                summary_data = cur.fetchone()
            
            if summary_data:
                return render_template('assessment_summary.html', 
                                       reviewer_name=session['full_name'], 
                                       app=summary_data)
            flash("Error: Summary record not found.")
            return redirect(url_for('scoring_history'))
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/scoring_history')
def scoring_history():
    if 'user_id' in session and session.get('role') == 'reviewer':
        uID = session['user_id']
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                sql = """SELECT a.applicationID, u.fullName, u.userID, a.score, 
                                 a.applicationStatus, a.reviewDate 
                         FROM application a
                         JOIN user u ON a.studentID = u.userID
                         WHERE a.reviewerID = %s AND a.score IS NOT NULL
                         ORDER BY a.reviewDate DESC"""
                cur.execute(sql, (uID,))
                history_list = cur.fetchall()
            return render_template('scoring_history.html', reviewer_name=session['full_name'], history=history_list)
        finally:
            connection.close()
    return redirect(url_for('index'))

# --- 6. COMMITTEE ROUTES ---

@app.route('/committee_overview')
def committee_overview():
    if 'user_id' in session and session.get('role') == 'committee':
        data = get_dashboard_stats() # Call dynamic data helper
        return render_template('committee_overview.html', 
                               committee_name=session['full_name'], 
                               user_role='committee',
                               **data)
    return redirect(url_for('index'))

@app.route('/committee_dashboard')
def committee_dashboard():
    if 'user_id' in session and session.get('role') == 'committee':
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                # Fetches individual candidates for interview scheduling
                sql = """
                    SELECT a.applicationID, u.fullName as applicantName, a.score, s.faculty 
                    FROM application a 
                    JOIN user u ON a.studentID = u.userID 
                    JOIN student s ON a.studentID = s.studentID
                    LEFT JOIN INTERVIEW i ON a.applicationID = i.applicationID
                    WHERE a.score IS NOT NULL 
                    AND i.interviewID IS NULL
                    AND a.applicationStatus != 'Rejected'
                """
                cur.execute(sql)
                candidate_list = cur.fetchall()
            return render_template('committee_dashboard.html', 
                                   committee_name=session['full_name'], 
                                   candidates=candidate_list)
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/committee_portfolio')
def committee_portfolio():
    if 'user_id' in session and session.get('role') == 'committee':
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                # DYNAMIC SQL: Counts rows in application table where status is 'Awarded'
                sql = """
                    SELECT s.*, 
                    (SELECT COUNT(*) FROM application WHERE scholarshipID = s.scholarshipID AND applicationStatus = 'Awarded') as slotsUsed
                    FROM scholarship s
                """
                cur.execute(sql)
                programs = cur.fetchall()
            return render_template('committee_portfolio.html', committee_name=session['full_name'], scholarships=programs)
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/view_awarded_students/<sch_id>')
def view_awarded_students(sch_id):
    if 'user_id' in session and session.get('role') == 'committee':
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                # Get Scholarship Name for the header
                cur.execute("SELECT scholarshipName FROM scholarship WHERE scholarshipID = %s", (sch_id,))
                sch = cur.fetchone()
                
                # Fetch only students with 'Awarded' status
                sql = """
                    SELECT u.fullName, u.userID, u.email, a.reviewDate 
                    FROM application a
                    JOIN user u ON a.studentID = u.userID
                    WHERE a.scholarshipID = %s AND a.applicationStatus = 'Awarded'
                """
                cur.execute(sql, (sch_id,))
                students = cur.fetchall()
            return render_template('award_list.html', scholarship=sch, students=students)
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/committee_calendar')
def committee_calendar():
    if 'user_id' in session and session.get('role') == 'committee':
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                # ADDED i.interviewVenue to the query
                sql = """
                    SELECT i.interviewDate, i.interviewVenue, u.fullName as applicantName, 
                           u.userID, i.interviewStatus, a.applicationID
                    FROM INTERVIEW i
                    JOIN application a ON i.applicationID = a.applicationID
                    JOIN user u ON a.studentID = u.userID
                    WHERE i.interviewStatus = 'Scheduled'
                """
                cur.execute(sql)
                scheduled_interviews = cur.fetchall()
            return render_template('committee_calendar.html', 
                                   committee_name=session['full_name'], 
                                   interviews=scheduled_interviews)
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/committee/manager')
@app.route('/edit_scholarship/<sch_id>')
def committee_manager(sch_id=None):
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
        display_name = session.get('full_name')
        return render_template('committee_manager.html', admin_name=display_name, committee_name=display_name, sch=scholarship_data)
    return redirect(url_for('index'))

@app.route('/add_scholarship_submit', methods=['POST'])
def add_scholarship_submit():
    if 'user_id' in session and session.get('role') in ['admin', 'committee']:
        user_role = session.get('role')
        form_action = request.form.get('action')
        status = 'Published' if form_action == 'publish' else 'Draft'
        existing_id = request.form.get('scholarshipID')
        name = request.form.get('scholarshipName')
        criteria = request.form.get('scholarshipCriteria')
        deadline = request.form.get('deadline')
        faculty = request.form.get('faculty')
        description = request.form.get('description')
        terms = request.form.get('termAndCondition')
        try:
            raw_amount = request.form.get('scholarshipAmount', '0')
            clean_amount = ''.join(filter(str.isdigit, str(raw_amount)))
            amount = int(clean_amount) if clean_amount else 0
            raw_slots = request.form.get('totalSlots', '0')
            slots = int(raw_slots) if raw_slots.isdigit() else 0
        except Exception as type_err:
            return f"Data Format Error: {type_err}"
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                if existing_id:
                    sql = """UPDATE scholarship SET 
                             scholarshipName=%s, scholarshipCriteria=%s, deadline=%s, 
                             scholarshipAmount=%s, termAndCondition=%s, faculty=%s, 
                             totalSlots=%s, description=%s, status=%s 
                             WHERE scholarshipID=%s"""
                    cur.execute(sql, (name, criteria, deadline, amount, terms, faculty, slots, description, status, existing_id))
                else:
                    sch_id = generate_sequential_id('SCH', 'scholarship', 'scholarshipID')
                    sql = """INSERT INTO scholarship 
                             (scholarshipID, scholarshipName, scholarshipCriteria, 
                              deadline, scholarshipAmount, termAndCondition, 
                              faculty, totalSlots, description, status) 
                              VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
                    cur.execute(sql, (sch_id, name, criteria, deadline, amount, terms, faculty, slots, description, status))
            connection.commit()
            flash(f"Scholarship '{name}' saved successfully.")
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

@app.route('/schedule_interview_submit', methods=['POST'])
def schedule_interview_submit():
    if 'user_id' in session and session.get('role') == 'committee':
        app_id = request.form.get('applicationID')
        assign_date = request.form.get('assignDate')
        assign_time = request.form.get('assignTime')
        venue = request.form.get('venue') # Captured from the new Decision Hub input
        
        interview_datetime = f"{assign_date} {assign_time}:00"
        
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                int_id = str(uuid.uuid4())[:8]
                # SAVE VENUE TO DATABASE
                cur.execute("""INSERT INTO INTERVIEW (interviewID, applicationID, interviewDate, interviewStatus, interviewVenue) 
                               VALUES (%s, %s, %s, 'Scheduled', %s)""", 
                            (int_id, app_id, interview_datetime, venue))
                
                cur.execute("UPDATE application SET applicationStatus = 'Scheduled' WHERE applicationID = %s", (app_id,))
                
                # Fetch details for Notification
                cur.execute("""SELECT a.studentID, s.scholarshipName FROM application a 
                               JOIN scholarship s ON a.scholarshipID = s.scholarshipID 
                               WHERE applicationID = %s""", (app_id,))
                info = cur.fetchone()
                
                # Student Notification including Venue
                notif_id = str(uuid.uuid4())[:8]
                msg = f"Interview Assigned: {info['scholarshipName']}. Date: {assign_date}, Time: {assign_time}. Venue: {venue}."
                cur.execute("""INSERT INTO NOTIFICATION (notificationID, userID, message, status, timestamp, type) 
                               VALUES (%s, %s, %s, 'Unread', %s, 'Interview Update')""", 
                            (notif_id, info['studentID'], msg, datetime.now()))
                            
            connection.commit()
            flash("Interview slot confirmed and student notified.")
            return redirect(url_for('committee_dashboard'))
        except Exception as e:
            if connection: connection.rollback()
            return f"Error: {e}"
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/decision/<app_id>')
def committee_decision(app_id):
    if 'user_id' in session and session.get('role') == 'committee':
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                sql = """
                    SELECT 
                        a.applicationID, 
                        a.studentID, 
                        u.fullName, 
                        IFNULL(r.score, 0) as reviewerScore, 
                        IFNULL(r.feedbackComment, 'No feedback provided by reviewer.') as reviewerFeedback
                    FROM application a
                    JOIN user u ON a.studentID = u.userID
                    LEFT JOIN REVIEW r ON a.applicationID = r.applicationID
                    WHERE a.applicationID = %s
                """
                cur.execute(sql, (app_id,))
                applicant = cur.fetchone()
                
            if applicant:
                return render_template('committee_decision.html', 
                                       committee_name=session['full_name'], 
                                       applicant=applicant)
            else:
                flash("Error: Applicant record not found.")
                return redirect(url_for('committee_calendar'))
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/finalize_award', methods=['POST'])
def finalize_decision():
    if 'user_id' in session and session.get('role') == 'committee':
        app_id = request.form.get('applicationID')
        decision = request.form.get('status')
        
        # 1. Capture notes and strip whitespace to prevent "gibberish"
        int_notes = request.form.get('interviewNotes', '').strip()
        
        # Fallback: If input is too short or looks like junk, provide a professional default
        if len(int_notes) < 10:
            int_notes = "Interview successfully conducted. Candidate evaluated based on merit criteria."

        final_status = 'Awarded' if decision == 'Awarded' else 'Rejected'
        
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                # 2. Update INTERVIEW table with meaningful feedback
                cur.execute("UPDATE INTERVIEW SET interviewStatus='Completed', interviewResult=%s WHERE applicationID=%s", (int_notes, app_id))
                
                # 3. Update application table status to 'Awarded' to trigger slot deduction
                cur.execute("UPDATE application SET applicationStatus=%s WHERE applicationID=%s", (final_status, app_id))
                
                # 4. Fetch dynamic student and scholarship info for the notification
                cur.execute("""SELECT a.studentID, s.scholarshipName, a.scholarshipID 
                               FROM application a 
                               JOIN scholarship s ON a.scholarshipID = s.scholarshipID 
                               WHERE a.applicationID = %s""", (app_id,))
                info = cur.fetchone()

                if info:
                    student_id = info['studentID']
                    sch_name = info['scholarshipName']
                    
                    # 5. CONSOLIDATED DASHBOARD & NOTIFICATION LOGIC
                    # Correctly handles the movement from Pending to final status in Student Dashboard
                    if final_status == 'Awarded':
                        # Update Student Dashboard: Pending -1, Accepted +1
                        sql_dash = """UPDATE DASHBOARD SET acceptedApplications = acceptedApplications + 1, 
                                      pendingApplications = pendingApplications - 1 WHERE userID = %s"""
                        
                        msg = f"Congratulations! You have been awarded the {sch_name}. Please check your email for disbursement details."
                        notif_type = 'Award Alert'
                    else:
                        # Update Student Dashboard: Pending -1, Rejected +1
                        sql_dash = """UPDATE DASHBOARD SET rejectedApplications = rejectedApplications + 1, 
                                      pendingApplications = pendingApplications - 1 WHERE userID = %s"""
                        
                        msg = f"Application Update: Your application for {sch_name} was not approved. We encourage you to apply for other programs."
                        notif_type = 'System Alert'

                    # Execute the single dashboard update
                    cur.execute(sql_dash, (student_id,))

                    # 6. Save the notification record
                    notif_id = str(uuid.uuid4())[:8]
                    cur.execute("""INSERT INTO NOTIFICATION (notificationID, userID, message, status, timestamp, type) 
                                   VALUES (%s, %s, %s, 'Unread', %s, %s)""", 
                                (notif_id, student_id, msg, datetime.now(), notif_type))

            connection.commit()
            flash(f"Final decision saved: {final_status}")
            return redirect(url_for('committee_dashboard'))
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
                cur.execute("SELECT * FROM NOTIFICATION WHERE userID = %s ORDER BY timestamp DESC", (uID,))
                user_notifs = cur.fetchall()
                cur.execute("""SELECT a.*, s.scholarshipName FROM application a 
                               JOIN scholarship s ON a.scholarshipID = s.scholarshipID 
                               WHERE a.studentID = %s AND a.applicationStatus != 'Draft'""", (uID,))
                active_apps = cur.fetchall()
            return render_template('student_dashboard.html', user_id=uID, name=session.get('full_name'), applications=user_notifs, dashboard_apps=active_apps, app_count=len(active_apps))
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/scholarship_detail/<sch_id>')
def scholarship_detail(sch_id):
    if 'user_id' in session and session.get('role') in ['student', 'admin']:
        uID = session['user_id']
        role = session.get('role')
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                cur.execute("SELECT * FROM scholarship WHERE scholarshipID = %s", (sch_id,))
                scholarship_data = cur.fetchone()
                if not scholarship_data:
                    return redirect(url_for('scholarship_discovery'))
                student_data = None
                app_check = None
                if role == 'student':
                    cur.execute("SELECT * FROM student WHERE studentID = %s", (uID,))
                    student_data = cur.fetchone()
                    cur.execute("SELECT applicationStatus FROM application WHERE studentID = %s AND scholarshipID = %s", (uID, sch_id))
                    app_check = cur.fetchone()
                cur.execute("SELECT * FROM NOTIFICATION WHERE userID = %s ORDER BY timestamp DESC", (uID,))
                user_notifs = cur.fetchall()
            return render_template('scholarship_detail.html', user_id=uID, role=role, name=session.get('full_name'), admin_name=session.get('full_name'), student=student_data, sch=scholarship_data, applications=user_notifs, existing_status=app_check['applicationStatus'] if app_check else None)
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
                # 1. Fetch all applications for the student
                cur.execute("""SELECT a.*, s.scholarshipName 
                               FROM application a 
                               JOIN scholarship s ON a.scholarshipID = s.scholarshipID 
                               WHERE a.studentID = %s 
                               ORDER BY a.submissionDate DESC""", (uID,))
                user_apps = cur.fetchall()

                # 2. Logic to calculate counts for the tab headers
                # Ensure 'Rejected' is counted in completed_count
                active_count = sum(1 for a in user_apps if a['applicationStatus'] in ['Submitted', 'Under Review', 'Approved', 'Scheduled'])
                draft_count = sum(1 for a in user_apps if a['applicationStatus'] == 'Draft')
                completed_count = sum(1 for a in user_apps if a['applicationStatus'] in ['Awarded', 'Rejected'])

                # 3. Fetch notifications for the bell
                cur.execute("SELECT * FROM NOTIFICATION WHERE userID = %s ORDER BY timestamp DESC", (uID,))
                user_notifs = cur.fetchall()

                # 4. Fetch specific count of UNREAD notifications for the red badge
                cur.execute("SELECT COUNT(*) as total FROM NOTIFICATION WHERE userID = %s AND status = 'Unread'", (uID,))
                unread_data = cur.fetchone()
                unread_count = unread_data['total'] if unread_data else 0

            return render_template('tracking_hub.html', 
                                   user_id=uID, 
                                   name=session.get('full_name'), 
                                   applications=user_apps, 
                                   notifications=user_notifs, 
                                   unread_count=unread_count, # Corrected Badge Count
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
                cur.execute("SELECT * FROM NOTIFICATION WHERE userID = %s ORDER BY timestamp DESC", (uID,))
                user_notifs = cur.fetchall()
                return render_template('profile.html', user_id=uID, name=session.get('full_name'), student=student_data, applications=user_notifs, notifications=user_notifs)
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return redirect(url_for('index'))
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
            cur.execute("UPDATE user SET fullName=%s, email=%s, phone=%s WHERE userID=%s", (fullName, email, phone, uID))
            cur.execute("UPDATE student SET faculty=%s, course=%s, cgpa=%s, total_credits=%s WHERE studentID=%s", (faculty, course, cgpa, credits, uID))
        connection.commit()
        session['full_name'] = fullName
        flash("Profile updated successfully!") 
        
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
                # Check for existing non-draft applications
                cur.execute("""SELECT applicationStatus FROM application 
                               WHERE studentID = %s AND scholarshipID = %s 
                               AND applicationStatus != 'Rejected'""", (uID, schID))
                existing_app = cur.fetchone()
                
                if existing_app and existing_app['applicationStatus'] != 'Draft':
                    flash("Access Denied: You already have an active application for this scholarship.")
                    return redirect(url_for('tracking_hub'))

                # Fetch basic student data
                cur.execute("""SELECT u.fullName, u.phone, s.cgpa, s.faculty 
                               FROM user u JOIN student s ON u.userID = s.studentID 
                               WHERE u.userID = %s""", (uID,))
                student_data = cur.fetchone()

                # Fetch existing draft if any
                cur.execute("""SELECT * FROM application 
                               WHERE studentID = %s AND scholarshipID = %s 
                               AND applicationStatus = 'Draft'""", (uID, schID))
                existing_draft = cur.fetchone()

                # Fetch scholarship info
                cur.execute("SELECT scholarshipName FROM scholarship WHERE scholarshipID = %s", (schID,))
                sch_info = cur.fetchone()

                # --- NOTIFICATION LOGIC (Fixes the UndefinedError) ---
                cur.execute("SELECT * FROM NOTIFICATION WHERE userID = %s ORDER BY timestamp DESC", (uID,))
                user_notifs = cur.fetchall()

                cur.execute("SELECT COUNT(*) as total FROM NOTIFICATION WHERE userID = %s AND status = 'Unread'", (uID,))
                unread_data = cur.fetchone()
                unread_count = unread_data['total'] if unread_data else 0

                return render_template('application_form.html', 
                                       student=student_data, 
                                       user_id=uID, 
                                       draft=existing_draft, 
                                       sch=sch_info,
                                       notifications=user_notifs, # Pass notifications
                                       unread_count=unread_count) # Pass unread_count
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/scholarship_discovery')
def scholarship_discovery():
    if 'user_id' in session and session.get('role') == 'student':
        selected_faculty = request.args.get('faculty', 'All')
        selected_cgpa = request.args.get('cgpa', '0.0')
        selected_category = request.args.get('category', 'All')
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                sql = "SELECT * FROM scholarship WHERE status = 'Published'"
                params = []
                if selected_cgpa != '0.0':
                    sql += " AND scholarshipCriteria <= %s"
                    params.append(float(selected_cgpa))
                if selected_category != 'All':
                    sql += " AND (scholarshipCriteria LIKE %s OR scholarshipName LIKE %s)"
                    params.extend([f"%{selected_category}%", f"%{selected_category}%"])
                if selected_faculty != 'All':
                    faculty_map = {
                        'FCI': ['Computing', 'Information', 'Technology','FCI', 'All'],
                        'FCM': ['Multimedia', 'Creative', 'Media', 'FCM', 'All'],
                        'FOB': ['Business', 'Accounting', 'Finance', 'Management', 'FOB', 'All'],
                        'FIST': ['Information', 'Science', 'Artificial Intelligence', 'FIST', 'All'],
                        'FOE': ['Engineering', 'Electrical', 'Mechanical', 'Civil', 'FOE', 'All'],
                        'FCA': ['Cinematic', 'Art', 'Animation', 'FCA', 'All']
                    }
                    keywords = faculty_map.get(selected_faculty, [selected_faculty])
                    keyword_placeholders = " OR ".join(["faculty LIKE %s"] * len(keywords))
                    sql += f" AND ({keyword_placeholders} OR faculty LIKE %s)"
                    for k in keywords:
                        params.append(f"%{k}%")
                    params.append("%All%")
                cur.execute(sql, tuple(params))
                published_list = cur.fetchall()
                cur.execute("SELECT * FROM NOTIFICATION WHERE userID = %s ORDER BY timestamp DESC", (session['user_id'],))
                user_notifs = cur.fetchall()
            return render_template('scholarship_discovery.html', scholarships=published_list, user_id=session.get('user_id'), name=session.get('full_name'), sel_faculty=selected_faculty, sel_cgpa=selected_cgpa, sel_category=selected_category, applications=user_notifs)
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/submit_application_data', methods=['POST'])
def submit_application_data():
    if 'user_id' in session:
        uID = session['user_id']
        data = request.form
        schID = data.get('scholarshipID')
        bank_choice = data.get('bank')
        other_name = data.get('other_bank_name')
        final_bank_name = other_name if bank_choice == 'Others' else bank_choice
        phone, semester = data.get('phone'), data.get('semester')
        activities, income = data.get('activities'), data.get('income')
        guardian_job, statement, bank_acc = data.get('guardianJob'), data.get('statement'), data.get('accNo')
        filename1, filename2 = "", ""
        
        # 文件处理逻辑保持不变...
        file1 = request.files.get('transcript')
        f1_size, f1_type = 0, ""
        if file1 and file1.filename != '':
            filename1 = secure_filename(f"{uID}_{schID}_transcript.pdf")
            f1_type = os.path.splitext(filename1)[1]
            file_path1 = os.path.join(app.config['UPLOAD_FOLDER'], filename1)
            file1.save(file_path1)
            f1_size = os.path.getsize(file_path1) // 1024 # KB

        file2 = request.files.get('income_proof')
        f2_size, f2_type = 0, ""
        if file2 and file2.filename != '':
            filename2 = secure_filename(f"{uID}_{schID}_income_proof.pdf")
            f2_type = os.path.splitext(filename2)[1]
            file_path2 = os.path.join(app.config['UPLOAD_FOLDER'], filename2)
            file2.save(file_path2)
            f2_size = os.path.getsize(file_path2) // 1024 # KB

        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                # 1. 更新或插入 APPLICATION 表
                cur.execute("SELECT applicationID FROM application WHERE studentID=%s AND scholarshipID=%s", (uID, schID))
                existing = cur.fetchone()
                
                if existing:
                    app_id = existing['applicationID']
                    sql = """UPDATE application SET 
                             submissionDate=%s, applicationStatus='Submitted', phone=%s, 
                             semester=%s, leadershipActivities=%s, householdIncome=%s, 
                             guardianOccupation=%s, statementOfPurpose=%s, bankAccNo=%s, 
                             bank=%s, documentUploaded=%s, incomeProof=%s WHERE applicationID=%s"""
                    cur.execute(sql, (datetime.now(), phone, semester, activities, income, guardian_job, statement, bank_acc, final_bank_name, filename1, filename2, app_id))
                else:
                    app_id = str(uuid.uuid4())[:8]
                    sql = """INSERT INTO application 
                             (applicationID, submissionDate, applicationStatus, studentID, scholarshipID, 
                              phone, semester, leadershipActivities, householdIncome, 
                              guardianOccupation, statementOfPurpose, bankAccNo, bank, documentUploaded, incomeProof)
                             VALUES (%s, %s, 'Submitted', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
                    cur.execute(sql, (app_id, datetime.now(), uID, schID, phone, semester, activities, income, guardian_job, statement, bank_acc, final_bank_name, filename1, filename2))
                
                if filename1:
                    doc1_id = str(uuid.uuid4())[:8]
                    cur.execute("INSERT INTO DOCUMENT (documentID, applicationID, fileName, fileType, fileSizeKB, storagePath, uploadDate) VALUES (%s, %s, %s, %s, %s, %s, %s)", (doc1_id, app_id, filename1, f1_type, f1_size, f"static/uploads/{filename1}", datetime.now()))
                
                if filename2:
                    doc2_id = str(uuid.uuid4())[:8]
                    cur.execute("INSERT INTO DOCUMENT (documentID, applicationID, fileName, fileType, fileSizeKB, storagePath, uploadDate) VALUES (%s, %s, %s, %s, %s, %s, %s)", (doc2_id, app_id, filename2, f2_type, f2_size, f"static/uploads/{filename2}", datetime.now()))

                sql_dash = "UPDATE DASHBOARD SET totalApplications = totalApplications + 1, pendingApplications = pendingApplications + 1 WHERE userID = %s"
                cur.execute(sql_dash, (uID,))

                cur.execute("SELECT scholarshipName FROM scholarship WHERE scholarshipID = %s", (schID,))
                sch_res = cur.fetchone()
                sch_name = sch_res['scholarshipName'] if sch_res else "Scholarship"
                msg = f"System Update: MeritHub {sch_name} received."
                cur.execute("INSERT INTO NOTIFICATION (notificationID, userID, message, status, timestamp, type) VALUES (%s, %s, %s, 'Unread', %s, 'System Alert')", (str(uuid.uuid4())[:8], uID, msg, datetime.now()))
            
            connection.commit()
            flash("Application submitted successfully!")
            return redirect(url_for('tracking_hub', tab='active'))
        except Exception as e:
            if connection: connection.rollback()
            return f"Database Error: {e}"
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/save_draft', methods=['POST'])
def save_draft():
    if 'user_id' in session:
        data = request.form
        uID = session['user_id']
        schID = data.get('scholarshipID')
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
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
        bank_choice = request.form.get('bank')
        other_name = request.form.get('other_bank_name')
        final_bank_name = other_name if bank_choice == 'Others' else bank_choice
        phone, semester = data.get('phone'), data.get('semester')
        activities, statement = data.get('activities'), data.get('statement')
        income = data.get('income') or 0
        guardian_job, bank_acc = data.get('guardianJob'), data.get('accNo')
        
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
                    cur.execute(sql, (datetime.now(), phone, semester, activities, statement, income, guardian_job, bank_acc, final_bank_name, existing['applicationID']))
                else:
                    app_id = str(uuid.uuid4())[:8]
                    sql = """INSERT INTO application 
                             (applicationID, submissionDate, applicationStatus, studentID, scholarshipID, 
                              phone, semester, leadershipActivities, statementOfPurpose, householdIncome, 
                              guardianOccupation, bankAccNo, bank) 
                              VALUES (%s, %s, 'Draft', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
                    cur.execute(sql, (app_id, datetime.now(), uID, schID, phone, semester, activities, statement, income, guardian_job, bank_acc, final_bank_name))
            connection.commit()
            return redirect(url_for('tracking_hub', tab='drafts'))
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/delete_draft/<app_id>', methods=['POST'])
def delete_draft(app_id):
    if 'user_id' in session:
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                sql = "DELETE FROM application WHERE applicationID = %s AND studentID = %s AND applicationStatus = 'Draft'"
                cur.execute(sql, (app_id, session['user_id']))
            connection.commit()            
        except Exception as e:
            return f"Error: {e}"
        finally:
            connection.close()
    return redirect(url_for('tracking_hub', tab='drafts'))

def generate_sequential_id(prefix, table_name, column_name):
    connection = get_db_connection()
    try:
        with connection.cursor() as cur:
            cur.execute(f"SELECT {column_name} FROM {table_name} WHERE {column_name} LIKE %s ORDER BY {column_name} DESC LIMIT 1", (f"{prefix}%",))
            last_record = cur.fetchone()
            if not last_record:
                return f"{prefix}0001"
            last_id = last_record[column_name]
            try:
                num_part = last_id.replace(prefix, "")
                last_num = int(num_part)
                new_num = last_num + 1
                return f"{prefix}{new_num:04d}" 
            except (ValueError, TypeError):
                import time
                return f"{prefix}{int(time.time())}"
    finally:
        connection.close()

@app.route('/mark_read/<notif_id>')
def mark_read(notif_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    connection = get_db_connection()
    try:
        with connection.cursor() as cur:
            # Update the specific notification for this user
            sql = "UPDATE NOTIFICATION SET status = 'Read' WHERE notificationID = %s AND userID = %s"
            cur.execute(sql, (notif_id, session['user_id']))
        connection.commit()
    except Exception as e:
        print(f"Error updating notification: {e}")
    finally:
        connection.close()
    
    # Redirect back to where they were, or to the tracking hub
    return redirect(request.referrer or url_for('tracking_hub'))

def get_dashboard_stats():
    connection = get_db_connection()
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cur:
            # 1. Total Applications
            cur.execute("SELECT COUNT(*) as total FROM application")
            total_apps = cur.fetchone()['total']

            # 2. Review Completion Rate (Apps with scores / Total)
            cur.execute("SELECT COUNT(*) as completed FROM application WHERE score IS NOT NULL")
            completed = cur.fetchone()['completed']
            completion_rate = round((completed / total_apps * 100), 1) if total_apps > 0 else 0

            # 3. Total Funds Disbursed (Sum of Awarded Scholarships)
            cur.execute("""
                SELECT SUM(s.scholarshipAmount) as total_funds 
                FROM application a 
                JOIN scholarship s ON a.scholarshipID = s.scholarshipID 
                WHERE a.applicationStatus = 'Awarded'
            """)
            funds_res = cur.fetchone()
            total_funds = funds_res['total_funds'] if funds_res['total_funds'] else 0

            # 4. Award Distribution by Faculty
            cur.execute("""
                SELECT s.faculty, COUNT(*) as count 
                FROM application a 
                JOIN scholarship s ON a.scholarshipID = s.scholarshipID 
                WHERE a.applicationStatus = 'Awarded' 
                GROUP BY s.faculty
            """)
            fac_data = cur.fetchall()
            distribution = {}
            colors = ["var(--emerald)", "var(--nav-dark)", "var(--slate)"]
            for i, row in enumerate(fac_data):
                distribution[row['faculty']] = {
                    "percent": round((row['count'] / (completed or 1) * 100), 0),
                    "color": colors[i % len(colors)]
                }

            # 5. DYNAMIC Monthly Trend (Last 4 Months)
            cur.execute("""
                SELECT DATE_FORMAT(submissionDate, '%b') as month, COUNT(*) as count 
                FROM application 
                WHERE submissionDate >= DATE_SUB(NOW(), INTERVAL 4 MONTH)
                GROUP BY month 
                ORDER BY submissionDate ASC
            """)
            trend_results = cur.fetchall()
            max_count = max([row['count'] for row in trend_results]) if trend_results else 1
            trends = {"monthly": {row['month']: {"percent": (row['count'] / max_count) * 100} for row in trend_results}}

            # MODIFIED: Formatting logic to ensure correct display of "k" values
            return {
                "stats": {
                    "total_apps": "{:,}".format(total_apps),
                    "completion_rate": completion_rate,
                    # This will divide by 1000 and add 'k'. 
                    # If total_funds is 40,000, it will show "40k".
                    "total_funds": "{:,.0f}k".format(total_funds / 1000) if total_funds >= 1000 else total_funds
                },
                "trends": trends,
                "distribution": distribution
            }
    finally:
        if connection:
            connection.close() #
@app.route('/generate_system_report')
def generate_system_report():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('index'))

    # 1. Fetch the same data used by the dashboard
    data = get_dashboard_stats()
    
    # 2. Create a Byte stream for the PDF
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    # --- Header ---
    p.setFont("Helvetica-Bold", 20)
    p.drawString(50, height - 50, "MeritHub System Analytics Report")
    
    p.setFont("Helvetica", 10)
    p.drawString(50, height - 65, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    p.drawString(50, height - 78, f"Admin: {session.get('full_name')}")
    p.line(50, height - 85, width - 50, height - 85)

    # --- Section: Key Performance Indicators ---
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, height - 120, "Key Performance Indicators")
    
    p.setFont("Helvetica", 12)
    p.drawString(70, height - 145, f"• Total Applications Volume: {data['stats']['total_apps']}")
    p.drawString(70, height - 165, f"• Review Completion Rate: {data['stats']['completion_rate']}%")
    p.drawString(70, height - 185, f"• Total Funds Disbursed: RM {data['stats']['total_funds']}")

    # --- Section: Award Distribution by Faculty ---
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, height - 230, "Award Distribution by Faculty")
    
    y_pos = height - 255
    p.setFont("Helvetica", 11)
    for faculty, info in data['distribution'].items():
        p.drawString(70, y_pos, f"• {faculty}: {info['percent']}% of total awards")
        y_pos -= 20

    # --- Section: Application Trends ---
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, y_pos - 30, "Recent Monthly Trends")
    
    y_pos -= 55
    for month, trend_info in data['trends']['monthly'].items():
        p.drawString(70, y_pos, f"• {month}: {int(trend_info['percent'])}% relative activity")
        y_pos -= 20

    # --- Footer ---
    p.line(50, 50, width - 50, 50)
    p.setFont("Helvetica-Oblique", 8)
    p.drawString(50, 40, "Confidential - MeritHub Scholarship Management System Internal Document")

    p.showPage()
    p.save()

    # 3. Finalize buffer and send
    buffer.seek(0)
    filename = f"MeritHub_Report_{datetime.now().strftime('%Y%m%d')}.pdf"
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype='application/pdf')
        
if __name__ == '__main__':
    app.run(debug=True)