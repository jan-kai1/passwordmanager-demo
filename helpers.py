from flask import session, redirect,flash,jsonify
from functools import wraps
import string
import secrets

def loginrequired(func):
    @wraps(func)
    def wrapper(*args,**kwargs):
        if session.get('user') == None:
            flash("Login required!")
            return redirect("/login")
        else:
            #func(*args, **kwargs) CANT CALL FUNCTION ITSELF AGAIN, BECAUSE IT IS WRAPPED WILL CALL ANOTHER WRAPPED FUNCTION LEADING TO A LOOP
            #return original function if session exists
            return func(*args,**kwargs)
    return wrapper

def randompassword():
    #dont deal with punctuation yet
    characters = string.ascii_letters  + string.digits + string.digits
    password = ''.join(secrets.choice(characters) for i in range(12))
    return password
    # same as 
    # for i in range (12):
    #     password += secrets.choice(characters)
