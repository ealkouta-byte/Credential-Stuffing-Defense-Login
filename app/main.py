#req imports
import sqlite3
import bcrypt
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import FileResponse

#init fast api
app = FastAPI()

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
def signup(email: str=Form(...), emailConfirmation: str=Form(...), username: str=Form(...), password: str = Form(...)):

    if email != emailConfirmation:
        raise HTTPException(status_code=400, detail="Emails do not match")

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
