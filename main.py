import psycopg2
import csv
import uuid
import datetime
from OTXv2 import OTXv2

def get_addressip():
    domain = []
    ipaddress = []
    link = []
    variable = []
    otx = OTXv2("6e6d817e0babbb9989a0399412ad36d59d7cbdad5ae140ef66eff24fc29da5c5")
    pulse_id = [
            "65a25a78f0d1d9eca23de3e8",
            "65a78672cf81a1fb0544e7c6"
        ]
    for pulse in pulse_id:
        indicators = otx.get_pulse_indicators(pulse)

        for indicator in indicators:
            ips = {"indicator": indicator["indicator"], "type": indicator["type"]}

            if ips["type"] == "IPv4":
                mydict = {'id': addressid(), 'ipaddress': ips["indicator"],
                           'created_time': ctime(), 'updated_time': None, 'credibility': 1}
                ipaddress.append(mydict)

            elif ips["type"] == "URL":
                mydict = {'id': addressid(), 'url': ips["indicator"],
                          'created_time': ctime(), 'updated_time': None, 'credibility': 1}
                link.append(mydict)

            elif ips["type"] == "domain":
                mydict = {'id': addressid(), 'domainn': ips["indicator"],
                          'created_time': ctime(), 'updated_time': None, 'credibility': 1}
                domain.append(mydict)

            else:
                mydict = {'id': addressid(), 'address': ips["indicator"], 'address_type':  ips["type"],
                          'created_time': ctime(), 'updated_time': None, 'credibility': 1}
                variable.append(mydict)
    return ipaddress, link, domain, variable

def save_address_in_csv(all_address):
    if all_address[0]:
        fields = ["id", "ipaddress", "created_time", "updated_time", "credibility"]
        filename = "ipfiles.csv"
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fields)
            writer.writeheader()
            writer.writerows(all_address[0])
        insert_from_csv_2db(r"C:\Users\Nochi\Desktop\mini_corties\ipfiles.csv", "ip")

    if all_address[1]:
        fields = ["id", "url", "created_time", "updated_time", "credibility"]
        filename = "urlfiles.csv"
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fields)
            writer.writeheader()
            writer.writerows(all_address[1])

        insert_from_csv_2db(r"C:\Users\Nochi\Desktop\mini_corties\urlfiles.csv", "url")

    if all_address[2]:
        name = "reza"
        fields = ["id", "domainn", "created_time", "updated_time", "credibility"]
        filename = "domainfiles.csv"
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fields)
            writer.writeheader()
            writer.writerows(all_address[2])
        insert_from_csv_2db(r"C:\Users\Nochi\Desktop\mini_corties\domainfiles.csv", "domain_address")

    if all_address[3]:
        fields = ["id", "address", "address_type", "created_time", "updated_time", "credibility"]
        filename = "variablefiles.csv"
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fields)
            writer.writeheader()
            writer.writerows(all_address[3])
        insert_from_csv_2db(r"C:\Users\Nochi\Desktop\mini_corties\variablefiles.csv", "variable")

def insert_from_csv_2db(csv_filename, table_name):
    conn, cursor = get_connection()
    schema = 'corties'
    full_table_name = f'{schema}.{table_name}'
    new_table = f'{schema}.like{table_name}'
    conflict_columns = {
    'corties.ip': 'ipaddress',
    'corties.url': 'url',
    'corties.domain_address': 'domainn',
    'corties.variable': 'address'}

    create_table_query = f"""
    DROP TABLE IF EXISTS {new_table} CASCADE;
    CREATE TABLE {new_table} AS SELECT * FROM {full_table_name} WITH NO DATA;
"""
    cursor.execute(create_table_query)
    conn.commit()

    # csvfile = open(csv_filename, 'r')
    # csvfile.close()

    with open(csv_filename, 'r') as csvfile:
        next(csvfile)
        query = f"COPY {new_table} FROM STDIN WITH CSV HEADER QUOTE '\"';"
        cursor.copy_expert(sql=query, file=csvfile)

        conn.commit()
        conn.close()

    current_conflict_column = conflict_columns[full_table_name]

    insert_query = f"""
    INSERT INTO {full_table_name}
    SELECT DISTINCT ON (id) *
    FROM {new_table}
    ON CONFLICT ({current_conflict_column}) DO UPDATE
    SET credibility = {full_table_name}.credibility + 1, updated_time = %s;
"""
    values = (ctime(), )
    insert_2db(insert_query, values)

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

def addressid():
    idaddress = str(uuid.uuid4())
    return idaddress

def ctime():
    current_time = str(datetime.datetime.now())[:19]
    return current_time

all_address = get_addressip()
save_address_in_csv(all_address)
