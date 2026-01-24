from flask import Flask, render_template, request, redirect, url_for, session, flash
import pymysql.cursors # Using pymysql as verified in test.py

app = Flask(__name__)

# --- 1. Secret Key (Required for sessions) ---
app.secret_key = 'super_secret_key_123' 

# --- 2. Database Connection Function ---
def get_db_connection():
    # Connect to the database using pymysql
    return pymysql.connect(
        host='localhost',
        user='root',
        password='',
        db='software engineering',
        cursorclass=pymysql.cursors.DictCursor
    )

@app.route('/')
def index():
    return render_template('main screen.html')

@app.route('/register_page')
def show_register_page():
    return render_template('student_register.html')

@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        # Get form data
        uID = request.form.get('studentID')
        fullName = request.form.get('fullName')
        email = request.form.get('new_reg_email')        
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
            
            # Log user in immediately
            session['user_id'] = uID
            session['full_name'] = fullName
            return redirect(url_for('student_dashboard')) 

        except Exception as e:
            connection.rollback()
            print(f"Error: {e}") 
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
        return redirect(url_for('student_dashboard'))
    else:
        return "Invalid User ID or Password. <a href='/'>Try again</a>"

@app.route('/forgot_password')
def forgot_password():
    return render_template('forgot_password.html')

@app.route('/verify_identity', methods=['POST'])
def verify_identity():
    uid = request.form.get('userid')
    email = request.form.get('email')

    connection = get_db_connection()
    try:
        with connection.cursor() as cur:
            # Check if User ID and Email match
            cur.execute("SELECT * FROM user WHERE userID = %s AND email = %s", (uid, email))
            user = cur.fetchone()
            
            if user:
                session['reset_user_id'] = uid 
                # DIRECTLY render the password page. 
                # The "Verification Done" popup is handled inside this HTML file.
                return render_template('reset_password.html')
            else:
                flash("Error: User ID and Email do not match our records.")
                return redirect(url_for('forgot_password'))
    finally:
        connection.close()

@app.route('/update_password', methods=['POST'])
def update_password():
    if 'reset_user_id' not in session:
        return redirect(url_for('index'))

    new_pwd = request.form.get('new_password')
    confirm_pwd = request.form.get('confirm_password')

    if new_pwd != confirm_pwd:
        flash("Passwords do not match!")
        return render_template('reset_password.html')

    user_id = session['reset_user_id']
    
    connection = get_db_connection()
    try:
        with connection.cursor() as cur:
            cur.execute("UPDATE user SET password = %s WHERE userID = %s", (new_pwd, user_id))
        connection.commit()
        
        session.pop('reset_user_id', None) # Clear temp session
        return render_template('reset_success.html')
    except Exception as e:
        connection.rollback()
        return f"Error updating password: {e}"
    finally:
        connection.close()

@app.route('/student_interface')
def student_dashboard():
    if 'user_id' in session:
        return render_template('student.html', name=session.get('full_name'))
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear() 
    return redirect(url_for('index')) 

if __name__ == '__main__':
    app.run(debug=True)