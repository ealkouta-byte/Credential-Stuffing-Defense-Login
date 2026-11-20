#req imports
import sqlite3
import bcrypt
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.breached_passwords import (check_breached_password, log_failed_login,check_new_password)
from time import time
from app.limiter import limiter

failed_by_user = {}  # username -> (fail_count, first_fail_time)
LOCKOUT_LIMIT = 4
LOCKOUT_SECONDS = 120

#init fast api
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# True = turn on the three new defenses
# False = turn off the three new defenses
PROTECTED = True
limiter.enabled = PROTECTED

app.mount("/static", StaticFiles(directory="static"), name="static")

#init db
db_file = "users.db"

#connect db
def get_db():
    return sqlite3.connect(db_file)

#create a table upon submission
def create_a_table():
    #fetch db
    db = get_db()
    #run query to create a table from login if user does not exist
    db.execute("CREATE TABLE IF NOT EXISTS users (email TEXT UNIQUE, username TEXT PRIMARY KEY, password_hash TEXT)")
    #save to the database
    db.commit()
    #close db connection
    db.close()

#this stops the crash on a fresh clone, because the server creates 
#an empty table on startup. Signup and login work right away, 
#just with no seeded users yet.
create_a_table()

#hash the passwords if they don't exist
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

#check if password typed is already saved
def check_password(password, stored_hash):
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

@app.get("/")
def root():
    return RedirectResponse("/signup-page.html")

#setup post action from form
@app.post("/signup")
def signup(email: str=Form(...), emailConfirmation: str=Form(...), username: str=Form(...), password: str = Form(...), passwordConfirmation: str = Form(...)):

    if email != emailConfirmation:
        raise HTTPException(status_code=400, detail="Emails do not match")

    if password != passwordConfirmation:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    # Reject breached passwords when protection is enabled
    check_breached_password(password, PROTECTED)

    #fetch current db
    db = get_db()

    #attempts to add email username and hash to database
    try:
        db.execute("INSERT INTO users VALUES (?,?,?)", (email, username, hash_password(password)))
        db.commit()

    #if it fails to save to db it will raise an error and print username or email already taken
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username or Email already taken")
    
    #safely close db
    finally:
        #close db
        db.close()

    return {"message": "Account created"}

#setup login action for login page
@app.post("/login")
@limiter.limit("4 per minute")
def login(request: Request, username: str = Form(...), password: str = Form(...)):

    #fetch db to use
    db = get_db()

    #get password hash to compare using username
    row = db.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()

    #disconnect db
    db.close()

    if PROTECTED:
        count, first_fail = failed_by_user.get(username, (0, 0))
        if count >= LOCKOUT_LIMIT and time() - first_fail < LOCKOUT_SECONDS:
            raise HTTPException(status_code=429, detail="Account temporarily locked")

    #if the hash is not in database check_password(password, row[0])
    if row is None or not check_password(password, row[0]):
        #record failed login attempts when protection is enabled
        log_failed_login(username, PROTECTED)
        #count this failure toward the account lockout
        if PROTECTED:
            count, first_fail = failed_by_user.get(username, (0, time()))
            failed_by_user[username] = (count + 1, first_fail)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    #a successful login clears any lockout counter for this account
    if PROTECTED:
        failed_by_user[username] = (0, 0)
    return {"message": "Login successful"}

#setup login action for change password page
@app.post("/changepass")

def change_password(username_or_email: str = Form(None), oldPassword: str = Form(...), newPassword: str = Form(...)):

    db = get_db()

    if not username_or_email:
        raise HTTPException(status_code=400, detail="Please enter a username or an email")
    
    row = db.execute("SELECT password_hash FROM users WHERE username = ? OR email = ?", (username_or_email, username_or_email)).fetchone()

    if row is None or not check_password(oldPassword, row[0]):

        db.close()

        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Check the new password before updating the database
    try:
        check_new_password(newPassword, PROTECTED)
    except HTTPException:
        db.close()
        raise

    db.execute("UPDATE users SET password_hash = ? WHERE username = ? OR email = ?", (hash_password(newPassword), username_or_email, username_or_email))

    db.commit()

    db.close()

    return{"message": "Password changed"}

@app.get("/signup-page.html")

def home():

    return FileResponse("static/signup-page.html")

@app.get("/login-serv-vuln1.html")

def login_page():

    return FileResponse("static/login-serv-vuln1.html")

@app.get("/change-pass.html")

def change_pass_page():

    return FileResponse("static/change-pass.html")