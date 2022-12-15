from flask import Flask, render_template, request, jsonify, redirect, session
from route.user import blueprint as user_blueprint
from services.database_Service import conn as cur
from dotenv import load_dotenv
from decimal import Decimal
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from sqlalchemy import text
import bcrypt
import requests
import jwt
import secrets
import re
import json

load_dotenv()
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

app.config["SECRET_KEY"] = "7eSEw7FDi6FHwBS7WyeVlrSjzWhGT4NW"
app.config["MAIL_PORT"] = 587
app.config["MAIL_SERVER"] = "imap.gmail.com"
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_DEFAULT_SENDER"] = "salsaasyifass@gmail.com"
app.config["MAIL_USERNAME"] = "salsaasyifass@gmail.com"
app.config["MAIL_PASSWORD"] = "gguobwupepbfxqzt"

mail = Mail(app)

app.register_blueprint(user_blueprint)

@app.route('/')
def hello_world():  # put application's code here
    return 'Hello! This is Asa!'

# Authentication

def otpHandler(data):
  otp = secrets.token_hex(3)
  session["otp"] = otp  # Store the OTP in the session
  msg = Message("Your OTP, Happy Coding!", recipients=[data['email']])
  msg.body = f"Your OTP is {otp}"
  mail.send(msg)

  return "Successfully sending OTP request! Please check your email!"

def checkUserAvailable(cur, data):
    result = cur.execute('SELECT * FROM user WHERE email=%s', (data['email'],))
    return result.rowcount > 0

def checkToken(bearer):
  try:
    token = bearer.split()[1]
    decodedToken = jwt.decode(token, "secret", algorithms=['HS256'])
    date_str = decodedToken['exp_date']
    tokenDate = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S")
    if (tokenDate < datetime.now()):
      raise

    return True
  except:
    return False

def checkOTP(otp):
  sessionOtp = session.get('otp')
  if (otp == sessionOtp):
    try:
      createUser()
    except:
      return "Failed to create user", 400

    session.clear()
    return "Success creating new account!", 201

  else: 
    return "Wrong OTP!", 200

def validEmail(email):
    regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if re.match(regex, email):
        return True
    return False

def createUser():
  data = session.get('user_cred')

  encodedPass = encodeStr(data['password'])

  cur.execute('INSERT INTO user(email, password) VALUES (%s, %s) ', (data['email'], encodedPass))

@app.route('/sign-up', methods=['GET', 'POST'])
def signUp():
  json_data = request.json

  otp = request.args.get('otp')
  if (otp):
    return checkOTP(otp)

  data = {
    'email': json_data['email'],
    'password': json_data['password']
    }
  session['user_cred'] = data

  if not validEmail(data['email']):
    return "Please enter a valid Email", 401

  if checkUserAvailable(cur, data):
    return "Your email or Password is already used!", 401

  else:
    try:
      res = otpHandler(data)
    except:
      return "Failed to send OTP! Please retry!", 400
    return res, 200

@app.route('/log-in', methods=['GET', 'POST'])
def logIn():
    json_data = request.json

    data = {
        "email": json_data['email'],
        "password": json_data['password'],
    }

    for user in cur.execute(' SELECT * FROM user WHERE email=%s LIMIT 1', (data['email'],)):
        if (verifyUser(data['password'], user['password'])):
            date = datetime.now() + timedelta(days=7)
            date_str = date.strftime("%Y-%m-%dT%H:%M:%S")
            token = jwt.encode({'exp_date' : date_str}, "secret")
            return jsonify(
                {
                'message': 'Please save this token and use it to access our provided API! This token will last for 7 Days',
                'token' : token
                }), 201
    return "No available email! Please sign in", 404

# Main App

@app.route('/pd', methods=['GET'])
def pd(): 
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404
    
  rows = []
  for pinfo in cur.execute("SELECT * FROM penerimaandana"):
    rows.append(pinfo)
  print(rows)
  pd_info = []
  
  for p in rows:
    pd_info.append({
      "id" : p[0],
      "Name Sekolah" : p[1],
      "NPSN" : p[2],
      "Status" : p[3],
      "Penerimaan dana 1": str(p[4]),
      "Penerimaan dana 2": str(p[5]),
      "Penerimaan dana 3": str(p[6]),
      "Penerimaan dana 4": str(p[7])
    })
  print(pd_info)
  return jsonify(pd_info)

@app.route('/playerByID', methods=['GET'])
def playerByID(): 
  id = request.args.get('id')
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404
    
  rows = []
  for pinfo in cur.execute("SELECT * FROM penerimaandana WHERE id = {pid}".format(pid = id)):
    rows.append(pinfo)
  player_info = []
  
  for p in rows:
    player_info.append({
      "id" : p[0],
      "Name Sekolah" : p[1],
      "NPSN" : p[2],
      "Status" : p[3],
      "Penerimaan dana 1": str(p[4]),
      "Penerimaan dana 2": str(p[5]),
      "Penerimaan dana 3": str(p[6]),
      "Penerimaan dana 4": str(p[7])
    })
  print(player_info)
  return jsonify(player_info)

@app.route('/dana-infrastruktur', methods=['GET'])
def danaInfrastruktur(): 
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404
    
  rows = []
  for pinfo in cur.execute("SELECT * FROM penerimaandana"):
    rows.append(pinfo)
  print(rows)
  pd_info = []
  
  for p in rows:
    total = p[4] + p[5] + p[6] + p[7]
    hitung = total * Decimal(0.3)
    pd_info.append({
      "Name Sekolah" : p[1],
      "Dana Infrastukrur": str(hitung)
    })
  print(pd_info)
  return jsonify(pd_info)



@app.route('/write-pd', methods=['POST'])
def writePD():
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404
  
  body = request.json

  payload = {
    "Nama Sekolah" : body["Nama Sekolah"],
    "NPSN" : body["NPSN"],
    "Status" : body["Status"],
    "Penerimaan dana 1": body["Penerimaan dana 1"],
    "Penerimaan dana 2": body["Penerimaan dana 2"],
    "Penerimaan dana 3": body["Penerimaan dana 3"],
    "Penerimaan dana 4": body["Penerimaan dana 4"]
  }
  cur.execute("INSERT INTO penerimaandana (Nama_Sekolah, NPSN, Status, Penerimaan_Dana_TW_1_Rp, Penerimaan_Dana_TW_2_Rp, Penerimaan_Dana_TW_3_Rp, Penerimaan_Dana_TW_4_Rp) VALUES (%s, %s, %s, %s, %s, %s, %s)", (payload['Nama Sekolah'], payload["NPSN"], payload["Status"], payload["Penerimaan dana 1"], payload["Penerimaan dana 2"], payload["Penerimaan dana 3"], payload["Penerimaan dana 4"]))
  return jsonify(payload)

@app.route('/update-pd', methods=['PUT'])
def updatePd():
  id = request.args.get('id')
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404


  body = request.json

  payload = {
    "ID" : id,
    "Nama Sekolah" : body["Nama Sekolah"],
    "NPSN" : body["NPSN"],
    "Status" : body["Status"],
    "Penerimaan dana 1": body["Penerimaan dana 1"],
    "Penerimaan dana 2": body["Penerimaan dana 2"],
    "Penerimaan dana 3": body["Penerimaan dana 3"],
    "Penerimaan dana 4": body["Penerimaan dana 4"]
  }
  
  cur.execute("UPDATE penerimaandana SET Nama_Sekolah = %s, NPSN = %s, Status = %s, Penerimaan_Dana_TW_1_Rp = %s, Penerimaan_Dana_TW_2_Rp = %s, Penerimaan_Dana_TW_3_Rp = %s, Penerimaan_Dana_TW_4_Rp = %s WHERE id = %s", (payload['Nama Sekolah'], payload["NPSN"], payload["Status"], payload["Penerimaan dana 1"], payload["Penerimaan dana 2"], payload["Penerimaan dana 3"], payload["Penerimaan dana 4"], payload['ID']))
  return jsonify(payload)


@app.route('/delete-pd', methods=['DELETE'])
def deletePd():
  id = request.args.get('id')
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404

  cur.execute("DELETE FROM penerimaandana WHERE id = %s", (id,))
  return f"Delete player success! [id = {id}]"

# @app.route('/useFTCore', methods=['GET'])
# def useFTCore():
#   auth_header = request.args.get("Authorization")

#   valid = checkToken(auth_header)

#   if not valid:
#     return "Token not valid", 404

#   body = request.json

#   dataLogin = {
#     'email' : body['email'],
#     'password': body['password'],
#     }

#   dataTeam = {
#     'Team 1 Id': body["Team 1 Id"],
#     'Team 2 Id': body["Team 2 Id"]
#   }

#   response = requests.post('http://206.189.80.94:5000/log-in', json = dataLogin)
#   result = response.json()
  
#   tokenKai = result['token']

#   response2 = requests.get('http://206.189.80.94:5000/winPredict?Authorization=Bearer %s' % (tokenKai), json = dataTeam)
#   result2 = response2.json()

#   winnerTeam = result2["Winner Team Prediction"]

#   rows = []
#   for winfo in cur.execute(text("SELECT * FROM `datasetplayer` WHERE Squad LIKE :sq ;"), {"sq" : f"%{winnerTeam}%"}):
#     rows.append(winfo)

#   mvpPredict =[]
#   for p in rows:
#     deci =  Decimal(6.0) + p[15] * Decimal(0.01) + p[24] * Decimal(0.01) + p[88] * Decimal(0.01) + p[92] * Decimal(0.01) + p[113] * Decimal(0.01) + p[126] * Decimal(0.01) + p[142] * Decimal(0.01)
#     mvpPredict.append({
#       "Rk" : p[0],
#       "Name" : p[1],
#       "Nation" : p[2],
#       "Position" : p[3],
#       "Rating": str('%.3f' % deci),
#     })

#   sorted_players = sorted(mvpPredict, key=lambda x: x['Rating'], reverse=True)
  
#   res = []
#   if len(sorted_players) > 5:
#     for i in range(5):
#       res.append(sorted_players[i])


#   response = {"Winner Team": winnerTeam, "MVP Prediction": res}
#   return jsonify(response)

# Auth

key = "JKE5UXZ3Q3IJQVXPQQC4NKNNO2XBFQ7R"

def encodeStr(ePass):
  hashed_password = bcrypt.hashpw((key+ePass).encode("utf-8"), bcrypt.gensalt())
  return hashed_password

def verifyUser(ePass, cPass):
  return bcrypt.checkpw((key+ePass).encode("utf-8"), cPass.encode("utf-8"))

if __name__ == '__main__':
    app.run()
