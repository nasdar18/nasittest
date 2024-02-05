import psycopg2
import uuid
from datetime import timedelta, datetime, date
from pydantic import BaseModel
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import FastAPI, HTTPException, status, Depends, Query
import hashlib
from psycopg2 import Error
import re
import requests
import json

app = FastAPI()

SECRET_KEY = "nasi@dri921116na!@#$%"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_connection():
    connection = psycopg2.connect(
        host="localhost",
        database="nasi",
        user="postgres",
        password="921116na")
    cursor = connection.cursor()
    return connection, cursor


def insert_2db(query, values=None):
    connection, cursor = get_connection()
    if values:
        cursor.execute(query, values)
    else:
        cursor.execute(query)
    connection.commit()
    connection.close()
    return True


def execute_query(query, values=None):
    connection, cursor = get_connection()

    try:
        if values:
            cursor.execute(query, values)
            affected_rows = cursor.rowcount
        else:
            cursor.execute(query)
            affected_rows = cursor.rowcount

        connection.commit()
        connection.close()
        return True, affected_rows
    except:
        return False, 0


def hash_password(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password


def addressid():
    idaddress = str(uuid.uuid4())
    return idaddress


def ctime():
    current_time = str(datetime.now())[:19]
    return current_time


def create_account(info):
    query = f"insert into userreports.users (id,username,password,created_time) values(%s,%s,%s,%s)"
    values = (addressid(), info.username, hash_password(info.password), ctime())

    try:
        insert_2db(query, values)
        return {"status_code": 200, "detail": "Your account has been created"}

    except Error as e:
        if 'duplicate key value violates unique constraint "username"' in str(e):
            raise HTTPException(status_code=401, detail=f"The username '{info.username}' have already taken")
        else:
            raise HTTPException(status_code=401, detail=f"Something Is Wrong")


def check_user_pass_from_db(username, password):
    conn, cursor = get_connection()
    select_user = f"select id, username, password from userreports.users where username = %s"
    values = (username, )
    cursor.execute(select_user, values)
    result = cursor.fetchone()
    if not result or result[2] != hash_password(password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    return {"id": result[0]}


def create_jwt_token(token_data):
    expiration_time = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token_data["exp"] = expiration_time
    return jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)


def decode_jwt_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp = payload.get("exp")
        if exp is None or exp < datetime.utcnow().timestamp():
            raise JWTError("Token has expired")
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_jwt_token(token)
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return payload


def check_indicator_type(indicator):
    ipaddress = re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", indicator)
    url = re.match(
        "^https?:\\/\\/(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)$",
        indicator)

    if ipaddress:
        return "IPv4"
    elif url:
        return "URL"
    else:
        return "domain"


def insert_user_reports_2db(detail, username, indicator_type):
    column = {"IPv4": "ipaddress",
              "URL": "url",
              "domain": "domainn"}

    table = {"IPv4": "ip",
             "URL": "url",
             "domain": "domain_address"}

    current_column = column[indicator_type]
    current_table = table[indicator_type]

    try:

        query = f"insert into userreports.reports (id,indicator_address,address_type,description,category,created_time,updated_time,report_by) values(%s,%s,%s,%s,%s,%s,%s,%s)"
        values = (addressid(), detail.indicator, indicator_type, detail.descriptipn, detail.category, ctime(), None, username)
        insert_2db(query, values)

        insert_query = f"insert into corties.{current_table} (id,{current_column},created_time,updated_time) values(%s,%s,%s,%s) on conflict ({current_column}) do update set credibility = {current_table}.credibility + 1, updated_time = %s"
        values = (addressid(), detail.indicator, ctime(), None, ctime())
        insert_2db(insert_query, values)
        return {"status_code": 200, "detail": "Thank you"}
    except:
        return {"status_code": 400, "detail": "Something Is Wrong"}


def select_indicator_details(indicator_type, indicator):
    column = {"IPv4": "ipaddress",
              "URL": "url",
              "domain": "domainn"}

    table = {"IPv4": "ip",
             "URL": "url",
             "domain": "domain_address"}

    current_column = column[indicator_type]
    current_table = table[indicator_type]
    userreports_list = []

    antivirus = get_information_from_virustotal(indicator, indicator_type)


    conn, cursor = get_connection()
    query1 = f"select id,credibility,created_time,updated_time from corties.{current_table} where {current_column} = %s"
    values = (indicator, )
    cursor.execute(query1, values)
    result1 = cursor.fetchone()

    query2 = f"select description,category,report_by from userreports.reports where indicator_address = %s"
    values = (indicator,)
    cursor.execute(query2, values)
    user_reports = cursor.fetchall()

    data_from_result1 = {"id": result1[0], "credibility": result1[1], "created_time": result1[2], "updated_time": result1[3]} if result1 else {"information": None}

    for item in user_reports:
        report_data = {"description": item[0],
                        "category": item[1],
                        "reporter": item[2]}
        userreports_list.append(report_data)


    indicator_data = {"indicator": indicator, "indicator_type": indicator_type}
    data_from_user_reports = {"reports": userreports_list} if user_reports else {"reports": None}
    data_from_antivirus = {"antiviruses": antivirus}
    combined_data = {**indicator_data, **data_from_result1, **data_from_user_reports, **data_from_antivirus}
    return combined_data


def get_information_from_virustotal(indicator, indicator_type):
    conn, cursor = get_connection()
    antivirus_list = []
    query = f"select * from virustotal.antiviruses where indicator_address = %s"
    values = (indicator,)
    cursor.execute(query, values)
    result = cursor.fetchone()

    try:
        d0 = datetime.strptime(result[2], '%Y-%m-%d %H:%M:%S')
        d1 = datetime.strptime(ctime(), '%Y-%m-%d %H:%M:%S')
        delta = d1 - d0
    except:
        delta = None


    if result and delta.days <= 3:
        antivirus_data = {"id": result[0],
                              "antiviruses": json.loads(result[1]),
                              "created_time": result[2]}

        antivirus_list.append(antivirus_data)
        return antivirus_list

    if result is None or delta is None or delta.days >= 4:
        address = {"IPv4": "ip_addresses",
                 "URL": "urls",
                 "domain": "domains"}
        current_address = address[indicator_type]

        url = f"https://www.virustotal.com/api/v3/{current_address}/{indicator}"
        headers = {'x-apikey': '482c95ed25a4c69152a5c47d29b5c07b880fb5a2ec9b0c33235e73e054c71abe'}
        response = requests.get(url, headers=headers)
        antiviruses = []
        updated_antivirus_list = []

        if response.status_code == 200:
            data = response.json()
            data = data["data"]["attributes"]["last_analysis_results"]
            for item in data:
                body = data[item]
                antiviruses.append(body)

            updated_antivirus = {
                "id": addressid(),
                "antiviruses": antiviruses,
                "created_time": ctime()
            }
            updated_antivirus_list.append(updated_antivirus)

            query = f"insert into virustotal.antiviruses (id,antiviruses,created_time,indicator_address) values(%s,%s,%s,%s) on conflict (indicator_address) do update set antiviruses = %s, created_time = %s"
            values = (updated_antivirus["id"], json.dumps(updated_antivirus["antiviruses"]), updated_antivirus["created_time"], indicator, json.dumps(antiviruses), ctime())
            insert_2db(query, values)
            return updated_antivirus


class users_information(BaseModel):
    username: str
    password: str


class indicator_by_users(BaseModel):
    indicator: str
    descriptipn: str
    category: str = Query("spam", regex=r"^spam$|^web$|^email$|^network$|^portscan")


@app.post("/signup")
def create_profile(info: users_information):
    result = create_account(info)
    if result:
        return result


@app.post("/login")
async def login_for_access_token(request: OAuth2PasswordRequestForm = Depends()):
    username = request.username
    password = request.password
    userid = check_user_pass_from_db(username, password)
    token_data = {"sub": username, "id": userid.get('id')}
    token = create_jwt_token(token_data)
    return {"access_token": token, "token_type": "bearer", "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES}


@app.post("/indicator")
def report_indicator(detail: indicator_by_users, token_payload: dict = Depends(get_current_user)):
    indicator_type = check_indicator_type(detail.indicator)
    result = insert_user_reports_2db(detail, token_payload.get('sub'), indicator_type)
    if result:
        return result


@app.get("/indicator")
def view_indicator_detail(indicator: str, token_payload: dict = Depends(get_current_user)):
    indicator_type = check_indicator_type(indicator)
    result = select_indicator_details(indicator_type, indicator)
    if result:
        return result


