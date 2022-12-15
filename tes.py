# Module Imports
import sys
from flask import Flask, request, jsonify
import json
from functools import wraps
import sqlalchemy
from sqlalchemy.orm import sessionmaker, scoped_session
import pymysql

def connect_unix_socket() -> sqlalchemy.engine.base.Engine:

    pool = sqlalchemy.create_engine(
        # Equivalent URL:
        # mysql+pymysql://<db_user>:<db_pass>@/<db_name>?unix_socket=<socket_path>/<cloud_sql_instance_name>
        sqlalchemy.engine.url.URL.create(
            drivername="mysql+pymysql",
            username="root",
            password="salsabilaas",
            database="tubes_tst",
            query={"unix_socket": "/cloudsql/tubes-tst-371605:asia-southeast2:tubes-tst"},
        ),
        # ...
    )
    return pool
# engine = sqlalchemy.create_engine('mysql+pymysql://root:salsabilaas@34.101.123.23:3306/tubes_tst')
engine = connect_unix_socket()

def getDanaSetahun(cur, id):
    rows = cur.execute(
        f"SELECT Penerimaan_Dana_TW_1_Rp + Penerimaan_Dana_TW_2_Rp + Penerimaan_Dana_TW_3_Rp + Penerimaan_Dana_TW_4_Rp AS total FROM penerimaandana WHERE id={id}"
    )
    row_headers=[x[0] for x in cur.description]
    rows = cur.all()
    json_data= None
    for result in rows:
        json_data=(dict(zip(row_headers,result)))
    
    return json_data

getDanaSetahun(engine,1)