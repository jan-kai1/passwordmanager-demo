from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify
import os, random, re
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_ , and_
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from helpers import loginrequired, randompassword
from markupsafe import Markup
from flask_migrate import Migrate
import json
import html

secretkey = os.urandom(12)
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(hours=2)
app.secret_key = secretkey
db = SQLAlchemy(app)
#FOR EDITING TABLES WHEN NEEDED
migrate = Migrate(app, db)
#TODO FIX LOGIN REQUIRED WRAPPER


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True, autoincrement = True, nullable = False)
    username = db.Column(db.String, nullable = False)
    masterpassword = db.Column(db.String, nullable = False)
    profiles = db.relationship("Profile", backref = 'user', lazy = True)

    def __init__(self,  username, masterpassword, id = None):
        self.id = id
        self.username = username
        self.masterpassword = masterpassword

    def __repr__(self):
        return(f"Username: {self.username}, password {self.masterpassword}, id {self.id}")
    
    
class Profile(db.Model):
    #should create way to update by date? but do you store old passwords?
    __tablename__ = 'profiles'
    id = db.Column(db.Integer, primary_key = True, autoincrement = True)
    websitename = db.Column(db.String, nullable = False)
    password = db.Column(db.String, nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable = False)
    
    # user = db.relationship("User", foreign_keys = 'User.id')

    def __init__(self, websitename, password, user_id, id = None):
        self.websitename = websitename
        self.password = password
        self.user_id = user_id
    
    def __repr__(self):
        return (f"{self.websitename}: {self.password}")
        
#create tables if not already exising
with app.app_context():
    db.create_all()

@app.route("/", methods = ['GET',"POST"])
def index():
    return render_template("index.html")

@app.route("/register", methods = ["GET","POST"])
def register():

    if request.method == "POST":
        #add to database
        if request.method == "POST":
            newusername = request.form.get('username').lower()
            password = request.form.get('password')
            confirmation  = request.form.get('confirmation')
            #check if userinput is valid
            if not newusername or len(newusername.split())>1:
                flash("input a valid username", "info")
            elif not password or not confirmation:
                flash("Complete password input", "info")
            elif password != confirmation:
                flash("Passwords do not match", "info")
            else:
                #check if user is in database
                #only select username
                existing = db.session.execute(db.select(User.username).where(User.username == newusername)).scalars().first()
                #.scalars will return a list(scalar object) of objects that match the criteria, .first() to access only the first one
                #returns a string of username if already exists
                if existing:
                    
                    flash(f'{existing} already exists, choose a different username')
                    return render_template("register.html", existing = existing)
                else:
                #add user to database
                
                    newhash = generate_password_hash(password, method='pbkdf2:sha256',salt_length=16)
                    newuser = User(username = newusername, masterpassword = newhash)
                    db.session.add(newuser)
                    db.session.commit()
                    
                    flash("Registered")
                    return redirect(url_for("login"))
    if request.method == "GET":
        return render_template("register.html")
    
@app.route("/login", methods = ['GET', 'POST'])
def login():
    #TODO FINISH UP LOGIN 
    if request.method == "POST":
        #check if user in database
        checkusername = request.form.get('username').lower()
        checkpassword = request.form.get('password')
        
        # db.session.execute executes sql code 
        #db.select generates the sql code to pass into session.execute, selecting multiple columns user.username and user.id
        #selecting only User would result in a user object being returned
        userdata = db.session.execute(db.select(User.username, User.masterpassword, User.id).filter(User.username == checkusername)).fetchone()
    
    

        # userid = db.session.execute(db.select(User.id))
        if userdata:
            username = userdata[0]
            userpassword = userdata[1]
            userid = userdata[2]
            #check password
            if check_password_hash(str(userpassword), checkpassword):
                #login
                session['user'] = username
                session['id'] = userid
                return redirect('/' )
                #TODO redirect to profile page
            else:
                #if invalid
                flash(f"Invalid username password")
                return render_template("login.html")
        else:
            flash("Invalid username or password")
            return render_template("login.html")
    if request.method == 'GET':
        return render_template("login.html")
    
@app.route("/logout")
@loginrequired
def logout():
    key_list = list(session.keys()) #session.keys
    for key in key_list:
        session.pop(key)
    flash("Successfully logged out!")
    return render_template("login.html")



@app.route("/addpassword", methods = ['GET','POST'])
@loginrequired
def addpassword():
    
    #check if valid website name use regular expression(?)
    websiteregex = re.compile(r"(http(s)?)?(://)?(www)?(\w*)?\.(.*)\.(\w*)")
    passwordlist = []
    for i in range(10):
        password = randompassword()
        passwordsafe = Markup.escape(password)
        #Markup.escape returns a markup object which is not jsonifiable, change it back to a str 
        passwordlist.append(str(passwordsafe))

    # passwordlist_json = json.dumps(passwordlist, ensure_ascii= True)
    passwordlist_json = json.dumps(passwordlist)
    #USE MARKUP SAFE TO PREVENT ESCAPE CHARACTERS BREAKING JAVASCRIPT CODE
    if request.method == 'POST':
        newpassword = request.form.get('password')
        newwebsite = request.form.get('websitename')
        #value to check if generate is clicked
        for char in newpassword:
            if char.isalnum() == False:
                return render_template("addpasssword.html", passwordlist = passwordlist_json)
        generateclicked = request.form.get('generate_clicked')
        if generateclicked == False:
            if not newpassword or not newwebsite:
                flash('Input a website and password!')
                return render_template("addpassword.html", passwordlist = passwordlist_json)
        if newwebsite:
            try:
                websitebase =  websiteregex.search(newwebsite).group()
            except AttributeError as err:           
                
                    flash('Input a valid website!')
                    return render_template("addpassword.html", passwordlist = passwordlist)
            else: #if website base was found and newwebsite input 
                addedProfile = Profile(websitebase, newpassword, session['id'])
                db.session.add(addedProfile)
                db.session.commit()
                flash('Password profile added')
        
    return render_template('addpassword.html', passwordlist = passwordlist)
    
    
    
    
    
@app.route("/<user>", methods = ["POST","GET"])
@loginrequired
def userprofile(user):
    #TODO let user search for individual website passwords
    #TODO let user copy password
    userid = session['id']
    userprofiles = db.session.execute(db.select(Profile.websitename, Profile.password).filter(Profile.user_id == userid)).fetchall()
    passwordlist = []
    for profile in userprofiles:
        passwordlist.append(profile[1])
    #let user delete a password
    #make button, to edit password check name of button, form 1 form 2
    if request.method == "POST":
        #if user wants to delete profile
        for i in range(0, len(userprofiles)+1):
            if f"form{i}" in request.form:
                #get value of input in form{i}s button

                deletepassword = request.form[f'form{i}']
                #search for password under user and delete from database
                #scalar used to return entire profile object instead of fetchone which returns a row containing data of the profile object
                #scalar with profile select would return a profile object
                deleteuser = db.session.execute(db.select(Profile).filter(and_(Profile.user_id == userid, Profile.password == deletepassword))).scalar()
                if deleteuser:
                    db.session.delete(deleteuser)
                    db.session.commit()
                    flash('Profile Deleted')
                else:
                    flash('not found')

            #create one for editing password as well?
            elif f"formd{i}" in request.form:
                originalpassword = request.form[f"formd{i}"]
                newpassword = request.form.get('newpassword')
                for char in newpassword:
                    if char.isalnum() == False:
                        flash("no punctuation characters allowed")
                        return render_template("userprofile.html",userprofiles = userprofiles, passwordlist = json.dumps(passwordlist))
                    else:
                        continue
                changeuser = db.session.execute(db.select(Profile).filter(and_(Profile.user_id == userid, Profile.password == originalpassword))).scalar()
                if changeuser:
                    changeuser.password = newpassword
                    db.session.commit()
                    flash("password changed")
                    return render_template("userprofile.html",userprofiles = userprofiles, passwordlist = json.dumps(passwordlist))
                    

    #json.dumps passes strings with "" instead of ''
    return render_template("userprofile.html",userprofiles = userprofiles, passwordlist = json.dumps(passwordlist))







if __name__ == "__main__":


    app.run()
