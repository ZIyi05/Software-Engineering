from flask import Flask, render_template, request, redirect, url_for, session, flash
import pymysql.cursors

app = Flask(__name__)

# Secret Key is required for session and flash messages
app.secret_key = 'super_secret_key_123'

# --- Database Connection Function ---
def get_db_connection():
    return pymysql.connect(
        host='localhost',
        user='root',
        password='',
        db='software engineering',
        cursorclass=pymysql.cursors.DictCursor
    )

@app.route('/')
def index():
    # This serves the login page as the entry point
    return render_template('login.html')

@app.route('/register_page')
def show_register_page():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        # Collect data from registration form names
        uID = request.form.get('studentID')
        fullName = request.form.get('fullName')
        # Ensure your HTML input name for email is 'email'
        email = request.form.get('email')        
        password = request.form.get('password')
        phone = request.form.get('phone')
        gender = request.form.get('gender')
        dob = request.form.get('dob')
        faculty = request.form.get('faculty')
        course = request.form.get('course')
        address = request.form.get('address')
        
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                # Insert into user table
                cur.execute("""INSERT INTO user (userID, fullName, password, email, phone, gender) 
                               VALUES (%s, %s, %s, %s, %s, %s)""", 
                            (uID, fullName, password, email, phone, gender))
                
                # Insert into student table
                cur.execute("""INSERT INTO student (studentID, address, dob, faculty, course) 
                               VALUES (%s, %s, %s, %s, %s)""", 
                            (uID, address, dob, faculty, course))
            
            connection.commit()
            flash("Account successfully created! Please log in.")
            return redirect(url_for('index')) 

        except Exception as e:
            connection.rollback()
            return f"Database Error: {e}"
        finally:
            connection.close()

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
        # Redirecting to the dashboard route
        return redirect(url_for('student_dashboard')) 
    else:
        flash("Invalid User ID or Password.")
        return redirect(url_for('index'))

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
            # Verify the ID and Email match in the database
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
    user_id = session['reset_user_id']
    
    connection = get_db_connection()
    try:
        with connection.cursor() as cur:
            cur.execute("UPDATE user SET password = %s WHERE userID = %s", (new_pwd, user_id))
        connection.commit()
        session.pop('reset_user_id', None)
        return render_template('reset_success.html') 
            
    except Exception as e:
        connection.rollback()
        return f"Error updating password: {e}"
    finally:
            connection.close()

@app.route('/student_dashboard')
def student_dashboard():
    if 'user_id' in session:
        return render_template('student_dashboard.html', 
                               user_id=session.get('user_id'), 
                               name=session.get('full_name'))
    return redirect(url_for('index'))

@app.route('/scholarship_detail')
def scholarship_detail():
    if 'user_id' in session:
        uID = session['user_id']
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                # Fetch full data so we have the CGPA and Faculty for validation
                cur.execute("SELECT * FROM student WHERE studentID = %s", (uID,))
                student_data = cur.fetchone()
                
                return render_template('scholarship_detail.html', 
                                       user_id=uID, 
                                       name=session.get('full_name'),
                                       student=student_data)
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/tracking_hub')
def tracking_hub():
    if 'user_id' in session:
        return render_template('tracking_hub.html', 
                               user_id=session.get('user_id'), 
                               name=session.get('full_name'))
    return redirect(url_for('index'))

@app.route('/profile') 
def profile():
    if 'user_id' in session:
        uID = session['user_id']
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                # Joining User and Student tables to get all profile fields
                sql = "SELECT * FROM user JOIN student ON user.userID = student.studentID WHERE user.userID = %s"
                cur.execute(sql, (uID,))
                student_data = cur.fetchone()
                
                return render_template('profile.html', 
                                       user_id=uID, 
                                       name=session.get('full_name'),
                                       student=student_data)
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
        flash("Profile updated successfully!")
        return redirect(url_for('profile'))
    except Exception as e:
        connection.rollback()
        return f"Database Error: {e}"
    finally:
        connection.close()

@app.route('/application_form')
def application_form():
    if 'user_id' in session:
        uID = session['user_id']
        connection = get_db_connection()
        try:
            with connection.cursor() as cur:
                # Fetch student and user details for pre-filling
                cur.execute("SELECT * FROM user JOIN student ON user.userID = student.studentID WHERE userID = %s", (uID,))
                data = cur.fetchone()
                return render_template('application_form.html', student=data, user_id=uID)
        finally:
            connection.close()
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)