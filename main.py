from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors

app = Flask(__name__)
app.secret_key = "user_authentication11"

# --- Database Configuration ---
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'software engineering'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor' 

mysql = MySQL(app)

@app.route('/')
def index():
    return render_template('main screen.html')

@app.route('/register_page')
def show_register_page():
    return render_template('student_register.html')

@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        uID = request.form.get('studentID')
        fullName = request.form.get('fullName')
        email = request.form.get('email')
        password = request.form.get('password') # Plain text for testing
        phone = request.form.get('phone')
        gender = request.form.get('gender')
        dob = request.form.get('dob')
        faculty = request.form.get('faculty')
        course = request.form.get('course')
        address = request.form.get('address')
        
        cur = mysql.connection.cursor()
        try:
            cur.execute("""INSERT INTO user (userID, fullName, password, email, phone, gender) 
                           VALUES (%s, %s, %s, %s, %s, %s)""", 
                        (uID, fullName, password, email, phone, gender))
            
            cur.execute("""INSERT INTO student (studentID, address, dob, faculty, course) 
                           VALUES (%s, %s, %s, %s, %s)""", 
                        (uID, address, dob, faculty, course))
            
            mysql.connection.commit()
            session['user_id'] = uID
            session['full_name'] = fullName
            return redirect(url_for('student_dashboard')) 
        except Exception as e:
            mysql.connection.rollback()
            return f"Database Error: {e}"
        finally:
            cur.close()

@app.route('/login_submit', methods=['POST'])
def login_submit():
    uid = request.form.get('userid')
    pwd = request.form.get('password')

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM user WHERE userID = %s", (uid,))
    user = cur.fetchone()
    cur.close()

    # Plain text comparison for testing
    if user and user['password'] == pwd: 
        session['user_id'] = user['userID']
        session['full_name'] = user['fullName']
        return redirect(url_for('student_dashboard'))
    else:
        return "Invalid User ID or Password. <a href='/'>Try again</a>"

@app.route('/student_interface')
def student_dashboard():
    if 'user_id' in session:
        return render_template('student.html', name=session.get('full_name'))
    return redirect(url_for('index'))

# --- THE LOGOUT ROUTE ---
@app.route('/logout')
def logout():
    session.clear() # Clear all logged-in data
    return redirect(url_for('index')) # Go back to login screen

if __name__ == '__main__':
    app.run(debug=True)