from flask import Flask, render_template, request, redirect, session
from flask_pymongo import PyMongo
import json
import bcrypt
import bson
from pymongo import MongoClient
import gridfs
from io import BytesIO
import base64

app = Flask(__name__)

with open('env.json', 'r') as f:
    params = json.load(f)
     
app.secret_key = params['secret_key']

app.config["MONGO_URI"] = "mongodb://localhost:27017/myclassroom"
mongo = PyMongo(app)
conn = MongoClient("127.0.0.1", port=27017)
db = conn.myclassroom
fs = gridfs.GridFS(db)

@app.route('/')
def index():
    username = session.get('user')
    if username == None:
        return redirect('/login')
    
    user = mongo.db.users.find_one({"username":username})
    rooms = mongo.db.rooms.find({
        "$or":[{"admin": user['_id']} , { "members": {"$in": [user['_id']]} } ]
    })

    return render_template('index.html', rooms=rooms, username=username)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        designation = request.form.get('designation')
        password = request.form.get('password')
        cpassword = request.form.get('cpassword')

        user = mongo.db.users.find_one({
            "$or":[{"username":username}, {"email":email}]
        })

        if user:
            return redirect('/register')
        else:

            if password == cpassword:
                password = password.encode()
                salt = bcrypt.gensalt()
                hashed_password = bcrypt.hashpw(password, salt)

                mongo.db.users.insert_one({"email": email, "username":username, "password": hashed_password, "designation": designation})
                session['user'] = username
                return redirect('/')

            return redirect('/register')

    else:
        return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = mongo.db.users.find_one({"username":username})
        
        if user:
            password = password.encode()
            check_password = bcrypt.checkpw(password, user['password'])
            if check_password == True:
                session['user'] = username
                return redirect('/')
            else:
                return redirect('/login')
        
        else:
            return redirect('/login')

    else:
        return render_template('login.html')

@app.route('/createroom', methods=['GET', 'POST'])
def createroom():
    if request.method == 'POST':
        room_name = request.form.get('roomname')
        subject = request.form.get('subject')
        user = mongo.db.users.find_one({"username": session.get('user')})
        mongo.db.rooms.insert_one({"room_name":room_name, "subject": subject, "admin":user['_id'], "members":[]})
        return redirect('/')
    
    else:
        return render_template('createroom.html', username=session['user'])
    
@app.route('/joinroom', methods=['GET', 'POST'])
def joinroom():
    if request.method == 'POST':
        room_id = bson.ObjectId(request.form.get('roomid'))
    
        user = mongo.db.users.find_one({"username": session.get('user')})
        
        room = mongo.db.rooms.update_one({"_id": room_id}, {"$push":{"members": user['_id']} })
        return redirect('/')
    
    else:
        return render_template('joinroom.html', username=session['user'])

@app.route('/rooms/<string:room_id>', methods=['GET', 'POST'])
def room(room_id):
    if request.method == 'POST':
        room_id = bson.ObjectId(room_id)
        url = request.form.get('hidden_url')
        filename = request.form.get('file')
        link = request.form.get('hidden_link')
        message = request.form.get('message')
        file = request.files['file']
        mongo.save_file(file.filename, file)
        mongo.db.classworks.insert_one({"url":url, "filename":file.filename, "link":link, "message":message ,"room_id":room_id})

        return redirect('/rooms/'+ str(room_id))
       
    else:
        user = mongo.db.users.find_one({"username":session['user']})
        room_id = bson.ObjectId(room_id)
        room = mongo.db.rooms.find_one({"_id":room_id})
        admin_username = mongo.db.users.find_one({"_id":room['admin']})['username']

        classworks = mongo.db.classworks.find({"room_id":room_id})
        sample = list(classworks.clone())
        classworks2 = classworks.clone()
        
        ids = []
        files = []
        
        for classwork in classworks2:
            if classwork['filename'] != "":
                data = db.fs.files.find_one({"filename":classwork['filename']})
                ids.append(data['_id'])
            else:
                ids.append("")
        
        for id in ids:
            if id == "":
                files.append("")
            else:
                f = fs.get(id)
                output = BytesIO(f.read())
                binary = base64.b64encode(output.getvalue()).decode()
                files.append(binary)
        
        return render_template('room.html', room_name=room['room_name'], subject=room['subject'], username=session['user'], room_id=room_id, admin=room['admin'], user_id=user['_id'], classworks=classworks, length=len(sample), files=files, admin_username=admin_username)

@app.route('/rooms/<string:room_id>/people')
def people(room_id):
    room_id = bson.ObjectId(room_id)
    room = mongo.db.rooms.find_one({"_id": room_id})
    admin_id = room['admin']
    admin = mongo.db.users.find_one({"_id": admin_id})

    member_ids = room['members']
    members = []

    for id in member_ids:
        member = mongo.db.users.find_one({"_id": id})
        members.append(member)
    
    return render_template('people.html', members=members, admin=admin, room_id=room_id)


@app.route('/logout')
def logout():
    session['user'] = None
    return redirect('/')

@app.route('/sample/<filename>')
def sample(filename):
    data = db.fs.files.find_one({"filename":filename})
    fs_id = data['_id']
    file = fs.get(fs_id)
    
    output = BytesIO(file.read())
    binary = base64.b64encode(output.getvalue()).decode()

    return render_template('sample.html', binary=binary)

if __name__ == "__main__":
    app.run(debug=True)