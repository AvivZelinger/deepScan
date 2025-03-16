# populate_mysql.py

import pandas as pd
from sqlalchemy import create_engine

# החלף את הפרטים בהתאם להגדרות שלך
DB_USER = 'root'
DB_PASSWORD = 'admin'
DB_HOST = 'localhost'
DB_PORT = '3306'
DB_NAME = 'project'

# צור את ה-engine
engine = create_engine(f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}')

# נתוני טבלה לדוגמה עם מספר רב יותר של שדות
data = {
    'name': [
        'version', 'packet_length', 'timestamp',
        'source_ip', 'destination_ip', 'message_id',
        'status_code', 'payload_length', 'payload',
        'checksum', 'flags', 'priority',
        'session_id', 'error_code', 'retries'
    ],
    'size': [
        2, 4, 4,
        15, 15, 4,
        2, 2, 0,  # payload_length = 2, payload = dynamic
        4, 1, 1,
        4, 2, 1
    ],
    'type': [
        'int', 'int', 'float',
        'char', 'char', 'int',
        'int', 'int', 'char',
        'int', 'bool', 'int',
        'int', 'int', 'int'
    ],
    'length_field': [
        None, None, None,
        None, None, None,
        None, 'payload_length', None,
        None, None, None,
        None, None, None
    ]
}

df = pd.DataFrame(data)
print("Inserting the following data into ProtocolSizesAndType:")
print(df)

# הכנסת הנתונים לטבלה
df.to_sql('ProtocolSizesAndType', engine, if_exists='replace', index=False)
print("Data has been inserted into ProtocolSizesAndType.")
