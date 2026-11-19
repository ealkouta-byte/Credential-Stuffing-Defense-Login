import logging #records failed login attempts
from fastapi import HTTPException

#Create a log file for failed login attempts
#Creates security.log to keep information in, logs if level of login is warning or higher, format is date/time, level, message.
logging.basicConfig(
    filename="security.log",
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

with open("data/breached_passwords.txt") as f:
    BREACHED = set(line.strip() for line in f)

#Check if password has been in a data breach    
def breached_password(password):
    return password in BREACHED

#Will reject a breached password if the protection is on
def check_breached_password(password, protected):
    if protected and breached_password(password):
        raise HTTPException(status_code=400, detail="Password has been breached. Choose another password.")

# When PROTECTED is on, record the failed login attempts and username to the security log
def log_failed_login(username, protected):
    if protected:
        logging.warning(f"Failed login attempt for: {username}")

#Checks if PROTECTED is on and if the new password is a breached password
def check_new_password(new_password, protected):
    if protected:
        if breached_password(new_password):
            #Reject the password and ask the user to choose a different one
            raise HTTPException(status_code=400, detail="New password has been breached. Please choose another password.")