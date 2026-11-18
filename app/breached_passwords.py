import logging #records failed login attempts
import hashlib #creates hash to check if it is exposed
import requests #checks passwords against the breach database
from fastapi import HTTPException



#Create a log file for failed login attempts
#Creates security.log to keep information in, logs if level of login is warning or higher, format is date/time, level, message.
logging.basicConfig(
    filename="security.log",
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


#Check if password has been in a data breach
def breached_password(password):

    #hash the password with SHA-1 and make it uppercase
    hashed=hashlib.sha1(password.encode()).hexdigest().upper()

    #split the password into the first five characters and then the rest
    prefix=hashed[:5]
    suffix=hashed[5:]

    #search the breached password database by prefix
    try:
        response=requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)

        #verify if the request to the database was successful
        response.raise_for_status()

    #If database is unable to be reached, throw an error
    except requests.RequestException:
        raise HTTPException(status_code=503, detail="Password check unavailable")

    #iterates through each line of the breached password database
    for line in response.text.splitlines():

        #compare the returned hash ending to the suffix (our password hash ending)
        if line.split(":")[0]==suffix:

            #if the password was found in the database
            return True

    #if the password was not found in the database
    return False

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


