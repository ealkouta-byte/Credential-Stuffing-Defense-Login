#req imports
import sqlite3
import bcrypt
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

#init fast api
app = FastAPI()

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
    #save to the data base
    db.commit()
    #close db connection
    db.close()

#hash the passwords if they don't exist
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

#check if password typed is already saved
def check_password(password, stored_hash):
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

#setup post action from form
@app.post("/signup")
def signup(email: str=Form(...), emailConfirmation: str=Form(...), username: str=Form(...), password: str = Form(...), passwordConfirmation: str = Form(...)):

    if email != emailConfirmation:
        raise HTTPException(status_code=400, detail="Emails do not match")

    if password != passwordConfirmation:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    #fetch current db
    db = get_db()

    #attempts to add email username and hash to database
    try:
        db.execute("INSERT INTO users VALUES (?,?,?)", (email, username, hash_password(password)))
        db.commit()

    #if it fails to save to db it will except and print username already taken
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username or Email already taken")
    
    #safely close db
    finally:
        #close db
        db.close()

    return {"message": "Account created"}

#setup login action for login page
@app.post("/login")

def login(username: str = Form(...), password: str = Form(...)):

    #fetch db to use
    db = get_db()

    #get password hash to compare using username
    row = db.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()

    #disconnect db
    db.close()

    #if the hash is not in database check_password(password, row[0])
    if row is None or not check_password(password, row[0]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"message": "Login successful"}

@app.post("/changepass")

def change_password(username_or_email: str = Form(None), oldPassword: str = Form(...), newPassword: str = Form(...)):

    db = get_db()

    if not username_or_email:
        raise HTTPException(status_code=400, detail="Please enter a username or an email")
    
    row = db.execute("SELECT password_hash FROM users WHERE username = ? OR email = ?", (username_or_email, username_or_email)).fetchone()

    if row is None or not check_password(oldPassword, row[0]):

        db.close()

        raise HTTPException(status_code=401, detail="Invalid credentials")
    
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