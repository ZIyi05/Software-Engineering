from flask import Flask, render_template, request, redirect, url_for, session, flash
import pymysql.cursors
import uuid
from datetime import datetime
import os
from werkzeug.utils import secure_filename


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
            cur.execute("SELECT * FROM user WHERE userID = %s", (uid,))
            user = cur.fetchone()
    finally:
        connection.close()

    if user and user['password'] == pwd:
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
            cur.execute("INSERT INTO user (userID, fullName, password, email, role, status) VALUES (%s, %s, %s, %s, 'student', 'Active')", 
                        (data['studentID'], data['fullName'], data['password'], data['email']))
            cur.execute("INSERT INTO student (studentID, faculty, course, address, dob) VALUES (%s, %s, %s, %s, %s)", 
                        (data['studentID'], data['faculty'], data['course'], data['address'], data['dob']))
            
            # --- DASHBOARD CONNECTION ---
            # Initialize metrics for reporting
            cur.execute("""INSERT INTO DASHBOARD (userID, totalApplications, acceptedApplications, rejectedApplications, pendingApplications) 
                           VALUES (%s, 0, 0, 0, 0)""", (data['studentID'],))

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
                cur.execute("SELECT * FROM scholarship WHERE status != 'Archived' ORDER BY deadline DESC")
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
                sql_revs = """
                    SELECT u.userID, u.fullName, 
                    (SELECT COUNT(*) FROM application WHERE reviewerID = u.userID) as current_load
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
        return render_template('reviewer_dashboard.html', reviewer_name=session['full_name'])
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
                cur.execute("SELECT COUNT(*) as total FROM application WHERE reviewerID = %s", (uID,))
                total_assigned = cur.fetchone()['total']
                cur.execute("SELECT COUNT(*) as completed FROM application WHERE reviewerID = %s AND score IS NOT NULL", (uID,))
                completed_count = cur.fetchone()['completed']
            return render_template('reviewer_queue.html', reviewer_name=session['full_name'], pending_tasks=pending_list, total=total_assigned, done=completed_count, remain=len(pending_list))
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
        recommendation = request.form.get('recommendation') 
        
        # Logic: Only explicitly 'Rejected' apps change status; others stay 'Under Review'
        new_status = 'Rejected' if recommendation == 'Rejected' else 'Under Review'
        
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                # 1. Update application table (FIXED: Removed 'a.feedback')
                sql_app = """UPDATE application 
                             SET score = %s, applicationStatus = %s, reviewDate = %s 
                             WHERE applicationID = %s"""
                cur.execute(sql_app, (score, new_status, datetime.now(), app_id))
                
                # 2. Insert into REVIEW table (Using 'feedbackComment')
                rev_id = str(uuid.uuid4())[:8]
                sql_rev = """INSERT INTO REVIEW (reviewID, applicationID, reviewerID, score, feedbackComment, reviewDate, stage) 
                             VALUES (%s, %s, %s, %s, %s, %s, %s)"""
                cur.execute(sql_rev, (rev_id, app_id, reviewer_id, score, feedback, datetime.now(), 'Evaluation Phase'))

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
        stats = {'total_apps': 1242, 'completion': '92%', 'funds': 'RM 500k'}
        return render_template('committee_overview.html', committee_name=session['full_name'], stats=stats)
    return redirect(url_for('index'))

@app.route('/committee_dashboard')
def committee_dashboard():
    if 'user_id' in session and session.get('role') == 'committee':
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                # UPDATED SQL: Added status check to exclude rejected applicants
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
                cur.execute("SELECT * FROM scholarship")
                programs = cur.fetchall()
            return render_template('committee_portfolio.html', committee_name=session['full_name'], scholarships=programs)
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/committee_calendar')
def committee_calendar():
    if 'user_id' in session and session.get('role') == 'committee':
        connection = get_db_connection()
        try:
            with connection.cursor(pymysql.cursors.DictCursor) as cur:
                sql = """
                    SELECT i.interviewDate, u.fullName as applicantName, u.userID, i.interviewStatus, a.applicationID
                    FROM INTERVIEW i
                    JOIN application a ON i.applicationID = a.applicationID
                    JOIN user u ON a.studentID = u.userID
                    WHERE i.interviewStatus = 'Scheduled'
                """
                cur.execute(sql)
                scheduled_interviews = cur.fetchall()
            return render_template('committee_calendar.html', committee_name=session['full_name'], interviews=scheduled_interviews)
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
        interview_datetime = f"{assign_date} {assign_time}:00"
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                int_id = str(uuid.uuid4())[:8]
                cur.execute("INSERT INTO INTERVIEW (interviewID, applicationID, interviewDate, interviewStatus) VALUES (%s, %s, %s, 'Scheduled')", (int_id, app_id, interview_datetime))
                cur.execute("UPDATE application SET applicationStatus = 'Scheduled' WHERE applicationID = %s", (app_id,))
                
                # --- SAVE NOTIFICATION FOR SCHEDULING ---
                cur.execute("SELECT studentID FROM application WHERE applicationID = %s", (app_id,))
                student_id = cur.fetchone()['studentID']
                notif_id = str(uuid.uuid4())[:8]
                msg = f"Interview Scheduled: Your session is set for {assign_date} at {assign_time}."
                cur.execute("""INSERT INTO NOTIFICATION (notificationID, userID, message, status, timestamp, type) 
                               VALUES (%s, %s, %s, 'Unread', %s, 'Interview Update')""", 
                            (notif_id, student_id, msg, datetime.now()))
            connection.commit()
            flash("Interview slot confirmed and student notified.")
            return redirect(url_for('committee_dashboard'))
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
        decision = request.form.get('status') # 'Awarded' or 'Rejected'
        int_notes = request.form.get('interviewNotes')
        
        # LOGIC: Final decision mapping
        final_status = 'Awarded' if decision == 'Awarded' else 'Rejected'
        
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                cur.execute("UPDATE INTERVIEW SET interviewStatus='Completed', interviewResult=%s WHERE applicationID=%s", (int_notes, app_id))
                cur.execute("UPDATE application SET applicationStatus=%s WHERE applicationID=%s", (final_status, app_id))
                
                if final_status == 'Awarded':
                    cur.execute("SELECT scholarshipID FROM application WHERE applicationID = %s", (app_id,))
                    res = cur.fetchone()
                    if res:
                        cur.execute("UPDATE scholarship SET totalSlots = totalSlots - 1 WHERE scholarshipID = %s AND totalSlots > 0", (res['scholarshipID'],))
                
                # Update DASHBOARD table
                cur.execute("SELECT studentID FROM application WHERE applicationID = %s", (app_id,))
                student_id = cur.fetchone()['studentID']
                if final_status == 'Awarded':
                    sql_dash = "UPDATE DASHBOARD SET acceptedApplications = acceptedApplications + 1, pendingApplications = pendingApplications - 1 WHERE userID = %s"
                else:
                    sql_dash = "UPDATE DASHBOARD SET rejectedApplications = rejectedApplications + 1, pendingApplications = pendingApplications - 1 WHERE userID = %s"
                cur.execute(sql_dash, (student_id,))

            connection.commit()
            flash(f"Final decision saved: {final_status}")
            return redirect(url_for('committee_dashboard'))
        except Exception as e:
            if connection: connection.rollback()
            return f"Error: {e}"
        finally:
            connection.close()
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
                cur.execute("SELECT a.*, s.scholarshipName FROM application a JOIN scholarship s ON a.scholarshipID = s.scholarshipID WHERE a.studentID = %s ORDER BY a.submissionDate DESC", (uID,))
                user_apps = cur.fetchall()
                active_count = sum(1 for a in user_apps if a['applicationStatus'] in ['Submitted', 'In Review', 'Scheduled'])
                draft_count = sum(1 for a in user_apps if a['applicationStatus'] == 'Draft')
                completed_count = sum(1 for a in user_apps if a['applicationStatus'] in ['Awarded', 'Rejected'])
                cur.execute("SELECT * FROM NOTIFICATION WHERE userID = %s ORDER BY timestamp DESC", (uID,))
                user_notifs = cur.fetchall()
            return render_template('tracking_hub.html', user_id=uID, name=session.get('full_name'), applications=user_apps, db_notifications=user_notifs, active_c=active_count, draft_c=draft_count, completed_c=completed_count)
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
                return render_template('profile.html', user_id=uID, name=session.get('full_name'), student=student_data, applications=user_notifs)
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
                cur.execute("""SELECT applicationStatus FROM application WHERE studentID = %s AND scholarshipID = %s AND applicationStatus != 'Rejected'""", (uID, schID))
                existing_app = cur.fetchone()
                if existing_app and existing_app['applicationStatus'] != 'Draft':
                    flash("Access Denied: You already have an active application for this scholarship.")
                    return redirect(url_for('tracking_hub'))
                cur.execute("SELECT u.fullName, s.cgpa, s.faculty FROM user u JOIN student s ON u.userID = s.studentID WHERE u.userID = %s", (uID,))
                student_data = cur.fetchone()
                cur.execute("SELECT * FROM application WHERE studentID = %s AND scholarshipID = %s AND applicationStatus = 'Draft'", (uID, schID))
                existing_draft = cur.fetchone()
                cur.execute("SELECT scholarshipName FROM scholarship WHERE scholarshipID = %s", (schID,))
                sch_info = cur.fetchone()
                return render_template('application_form.html', student=student_data, user_id=uID, draft=existing_draft, sch=sch_info)
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
        
        # File handling and tracking
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
                # 1. Update/Insert into APPLICATION table
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
                
                # --- DOCUMENT CONNECTION ---
                # Save metadata for reporting and file management
                if filename1:
                    doc1_id = str(uuid.uuid4())[:8]
                    sql_doc1 = """INSERT INTO DOCUMENT (documentID, applicationID, fileName, fileType, fileSizeKB, storagePath, uploadDate) 
                                 VALUES (%s, %s, %s, %s, %s, %s, %s)"""
                    cur.execute(sql_doc1, (doc1_id, app_id, filename1, f1_type, f1_size, f"static/uploads/{filename1}", datetime.now()))
                
                if filename2:
                    doc2_id = str(uuid.uuid4())[:8]
                    sql_doc2 = """INSERT INTO DOCUMENT (documentID, applicationID, fileName, fileType, fileSizeKB, storagePath, uploadDate) 
                                 VALUES (%s, %s, %s, %s, %s, %s, %s)"""
                    cur.execute(sql_doc2, (doc2_id, app_id, filename2, f2_type, f2_size, f"static/uploads/{filename2}", datetime.now()))

                # --- DASHBOARD CONNECTION (Total Count) ---
                # Increment total and pending counts for reporting
                sql_dash = "UPDATE DASHBOARD SET totalApplications = totalApplications + 1, pendingApplications = pendingApplications + 1 WHERE userID = %s"
                cur.execute(sql_dash, (uID,))

                # NOTIFICATION SAVE
                notif_id = str(uuid.uuid4())[:8]
                cur.execute("SELECT scholarshipName FROM scholarship WHERE scholarshipID = %s", (schID,))
                sch_res = cur.fetchone()
                sch_name = sch_res['scholarshipName'] if sch_res else "Scholarship"
                msg = f"System Update: MeritHub {sch_name} received."
                cur.execute("""INSERT INTO NOTIFICATION (notificationID, userID, message, status, timestamp, type) 
                               VALUES (%s, %s, %s, 'Unread', %s, 'System Alert')""", 
                            (notif_id, uID, msg, datetime.now()))
            
            connection.commit()
            flash("Application submitted and recorded!")
            return redirect(url_for('tracking_hub'))
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

if __name__ == '__main__':
    app.run(debug=True)