# Module Imports
import mariadb
import sys
from flask import Flask, request, jsonify
import json
import jwt 
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask_mail import Mail, Message
import pyotp

def hash_password(password):
  sha256 = hashlib.sha256()
  sha256.update(password.encode())
  hashed_password = sha256.hexdigest()
  return hashed_password

# Connect to MariaDB Platform
app = Flask(__name__)

app.config['SECRET_KEY'] = '7eSEw7FDi6FHwBS7WyeVlrSjzWhGT4NW'
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'salsaasyifass@gmail.com'
app.config['MAIL_PASSWORD'] = 'mawnhxpqabfstkqy'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)
totp = pyotp.TOTP('JKE5UXZ3Q3IJQVXPQQC4NKNNO2XBFQ7R', interval=120)

try:
    conn = mariadb.connect(
        user="salsabilaasyifa",
        password="tstkeren",
        host="localhost",
        port=3306,
        database="tubes_tst"
    )
except mariadb.Error as e:
    print(f"Error connecting to MariaDB Platform: {e}")
    sys.exit(1)

if(conn):
    cur = conn.cursor()

def token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
        if not token:
            return jsonify({'error' : 'Memerlukan akses token.'}), 401
        try:
          token = token.replace('Bearer ', '')
          data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
          current_user = getUserById(cur=cur, id=data['user_id'])
        except Exception as e:
          if(str(e) == 'Signature has expired'):
            return jsonify({'error' : 'Session telah berakhir! Mohon masuk kembali.'}), 401
          return jsonify({'error' : 'Token invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route("/kr")
@token
def kr(user):
    cur = conn.cursor()
    cur.execute(
    "SELECT * FROM kondisiruangan")
    row_headers=[x[0] for x in cur.description]
    rows = cur.fetchall()
    json_data=[]
    for result in rows:
        json_data.append(dict(zip(row_headers,result)))
    cur.close()
    return json.dumps({"kondisi ruangan": json_data})

@app.route("/pd")
@token
def pd(user):
    cur = conn.cursor()
    cur.execute(
    "SELECT * FROM penerimaandana")
    row_headers=[x[0] for x in cur.description]
    rows = cur.fetchall()
    json_data=[]
    for result in rows:
        json_data.append(dict(zip(row_headers,result)))
    cur.close()
    return json.dumps({"penerimaan dana": json_data})

@app.route("/delete-kr", methods=["DELETE"])
@token
def deleteKR(user):
    if request.method == "DELETE":
        cur = conn.cursor()
        id = request.args.get("id")
        cur.execute(
        f"DELETE FROM kondisiruangan WHERE ID = {id}")
        return json.dumps({"message" : "Berhasil menghapus data"})

@app.route("/delete-pd", methods=["DELETE"])
@token
def deletePD(user):
    if request.method == "DELETE":
        cur = conn.cursor()
        id = request.args.get("id")
        cur.execute(
        f"DELETE FROM penerimaandana WHERE ID = {id}")
        return json.dumps({"message" : "Berhasil menghapus data"})

@app.route("/update-kr", methods=["PUT"])
@token
def updKR(user):
    if request.method == "PUT":
        cur = conn.cursor()
        data = dict(request.json)
        print(data)
        id = data['id']
        nama_kecamatan = data["nama_kecamatan"]
        nama_sekolah = data["nama_sekolah"]
        baik = data["baik"]
        rusak_ringan = data["rusak_ringan"]
        rusak_sedang = data["rusak_sedang"]
        rusak_berat = data["rusak_berat"]
        jumlah_ruangan = data["jumlah_ruangan"]
        cur.execute(
        f'''UPDATE kondisiruangan 
            SET Nama_Kecamatan = '{nama_kecamatan}',
            Nama_Sekolah = '{nama_sekolah}',
            Baik = {baik},
            Rusak_Ringan = {rusak_ringan},
            Rusak_Sedang = {rusak_sedang},
            Rusak_Berat = {rusak_berat},
            Jumlah_Ruangan = {jumlah_ruangan}
            WHERE ID = {id}''')
        return json.dumps({"message" : "Berhasil memperbarui data"})

@app.route("/write-kr", methods=["POST"])
@token
def writeKR(user):
    if request.method == "POST":
        try:
            cur = conn.cursor()
            data = dict(request.json)
            id = data['id']
            nama_kecamatan = data["nama_kecamatan"]
            nama_sekolah = data["nama_sekolah"]
            baik = data["baik"]
            rusak_ringan = data["rusak_ringan"]
            rusak_sedang = data["rusak_sedang"]
            rusak_berat = data["rusak_berat"]
            jumlah_ruangan = data["jumlah_ruangan"]
            cur.execute(
            f'''INSERT INTO kondisiruangan (ID, Nama_Kecamatan, Nama_Sekolah, Baik, Rusak_Ringan, Rusak_Sedang, Rusak_Berat, Jumlah_Ruangan)
                VALUE({id}, '{nama_kecamatan}', '{nama_sekolah}', {baik}, {rusak_ringan}, {rusak_sedang}, {rusak_berat}, {jumlah_ruangan});''')
        except Exception as e:
            return json.dumps({"message": str(e)})
        return json.dumps({"message" : "Berhasil menambahkan data"})

@app.route("/update-pd", methods=["PUT"])
@token
def updPD(user):
    if request.method == "PUT":
        cur = conn.cursor()
        data = dict(request.json)
        id = data['ID']
        nama_sekolah = data["Nama_Sekolah"]
        NPSN = data["NPSN"]
        status = data["Status"]
        Penerimaan_Dana_TW_1_Rp = data["Penerimaan_Dana_TW_1_Rp"]
        Penerimaan_Dana_TW_2_Rp = data["Penerimaan_Dana_TW_2_Rp"]
        Penerimaan_Dana_TW_3_Rp = data["Penerimaan_Dana_TW_3_Rp"]
        Penerimaan_Dana_TW_4_Rp = data["Penerimaan_Dana_TW_4_Rp"]
        cur.execute(
        f'''UPDATE penerimaandana 
            SET Nama_Sekolah = '{nama_sekolah}',
            NPSN = {NPSN},
            Status = '{status}',
            Penerimaan_Dana_TW_1_Rp = {Penerimaan_Dana_TW_1_Rp},
            Penerimaan_Dana_TW_2_Rp = {Penerimaan_Dana_TW_2_Rp},
            Penerimaan_Dana_TW_3_Rp = {Penerimaan_Dana_TW_3_Rp},
            Penerimaan_Dana_TW_4_Rp = {Penerimaan_Dana_TW_4_Rp}
            WHERE ID = {id}''')
        return json.dumps({"message" : "Berhasil memperbarui data"})

@app.route("/write-pd", methods=["POST"])
@token
def writePD(user):
    if request.method == "POST":
        try:
            cur = conn.cursor()
            data = dict(request.json)
            id = data['ID']
            nama_sekolah = data["Nama_Sekolah"]
            NPSN = data["NPSN"]
            status = data["Status"]
            Penerimaan_Dana_TW_1_Rp = data["Penerimaan_Dana_TW_1_Rp"]
            Penerimaan_Dana_TW_2_Rp = data["Penerimaan_Dana_TW_2_Rp"]
            Penerimaan_Dana_TW_3_Rp = data["Penerimaan_Dana_TW_3_Rp"]
            Penerimaan_Dana_TW_4_Rp = data["Penerimaan_Dana_TW_4_Rp"]
            cur.execute(
            f'''INSERT INTO penerimaandana (ID, Nama_Sekolah, NPSN, Status, Penerimaan_Dana_TW_1_Rp, Penerimaan_Dana_TW_2_Rp, Penerimaan_Dana_TW_3_Rp, Penerimaan_Dana_TW_4_Rp)
                VALUE({id}, '{nama_sekolah}', {NPSN}, '{status}', {Penerimaan_Dana_TW_1_Rp}, {Penerimaan_Dana_TW_2_Rp}, {Penerimaan_Dana_TW_3_Rp}, {Penerimaan_Dana_TW_4_Rp});''')
        except Exception as e:
            return json.dumps({"message": str(e)})
        return json.dumps({"message" : "Berhasil menambahkan data"})

@app.route('/signup', methods=["POST"])
def signup():
    cur = conn.cursor()
    request_body = request.json

    body = {
        "name": request_body['name'],
        "username": request_body['username'],
        "password": request_body['password'],
        "email": request_body['email']
    }

    if checkUserAvailable(cur, body):
        return "Username is unavailable!"
    
    else:
        cur.execute(
            f"INSERT INTO user(name, username, password, email) VALUES ('{body['name']}', '{body['username']}', '{hash_password(body['password'])}', '{body['email']}')"
        )
        conn.commit()
        cur.close()
        return "New Account Created Successfully"
    
@app.route('/login', methods=["POST"])
def login():
    cur = conn.cursor()
    request_body = request.json

    body = {
        "username": request_body['username'],
        "password": request_body['password']
    }

    cur.execute(
        f"SELECT * FROM user WHERE username='{body['username']}'"
    )
    row_headers=[x[0] for x in cur.description]
    rows = cur.fetchall()
    
    json_data=None
    for result in rows:
        json_data=(dict(zip(row_headers,result)))
   
    if(json_data):
        if (hash_password(body['password'])==json_data["password"]):
            msg = Message(
            'OTP Asa',
            sender = app.config['MAIL_USERNAME'],
            recipients = [json_data['email']]
            )
            user_otp = totp.now()
            msg.body = f'Kode OTP Anda: {user_otp}. OTP Berlaku selama 2 menit. Selamat login ^_^'
            mail.send(msg)
            
            return jsonify({
                'message' : 'Silahkan cek OTP di email Anda.',
            }), 201
        
        else:
            return "Invalid Username/Password", 401
    
    return "Username Not Found", 404

@app.route('/verify-otp', methods=["GET"])
def verifyOTP():
    cur = conn.cursor()
    request_body = request.json

    body = {
        "username": request_body['username'],
        "otp": request_body['otp']
    }
    cur.execute(
        f"SELECT * FROM user WHERE username='{body['username']}'"
    )
    row_headers=[x[0] for x in cur.description]
    rows = cur.fetchall()
    
    json_data=None
    for result in rows:
        json_data=(dict(zip(row_headers,result)))

    if(json_data):
        token = jwt.encode({
            "user_id" : json_data["id"],
            "exp": datetime.utcnow() + timedelta(seconds=30)
        }, app.config['SECRET_KEY'])

        return jsonify({
                'message' : 'Save this token to access API',
                'token' : token
        }), 201

    else:
        return "Invalid Username", 401


def getUserById(cur, id):
    cur.execute(
        f"SELECT * FROM user WHERE id={id}"
    )
    row_headers=[x[0] for x in cur.description]
    rows = cur.fetchall()
    json_data= None
    for result in rows:
        json_data=(dict(zip(row_headers,result)))
    
    return json_data

def checkUserAvailable(cur, body):
    cur.execute(
        f"SELECT * FROM user WHERE username='{body['username']}'"
    )
    row_headers=[x[0] for x in cur.description]
    rows = cur.fetchall()
    json_data=[]
    for result in rows:
        json_data=(dict(zip(row_headers,result)))
    
    return json_data

if __name__ == "__main__":
    app.run(debug=True)
