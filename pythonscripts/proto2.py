# populate_mysql_protocol2.py

import pandas as pd
from sqlalchemy import create_engine

# הגדר את פרטי החיבור ל-MySQL
DB_USER = 'root'
DB_PASSWORD = 'admin'
DB_HOST = 'localhost'
DB_PORT = '3306'
DB_NAME = 'project'

# יצירת engine
engine = create_engine(f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}')

# הגדרת נתוני הפרוטוקול החדש
# עבור השדה "payload", הגודל יהיה 0 ויש להגדיר את עמודת length_field כך שיפנה ל-"payload_size"
data = {
    'name': [
        'header', 'version', 'msg_type', 'seq',
        'payload_size', 'payload',
        'timestamp', 'source', 'destination', 'checksum'
    ],
    'size': [
        2, 1, 10, 4,
        2, 0, 4, 15, 15, 4
    ],
    'type': [
        'int', 'int', 'char', 'int',
        'int', 'char',
        'float', 'char', 'char', 'int'
    ],
    'length_field': [
        None, None, None, None,
        None, 'payload_size',
        None, None, None, None
    ]
}

df = pd.DataFrame(data)
print("Inserting the following data into Protocol2Definition:")
print(df)

# הכנסה לטבלה (מחליפה את הטבלה אם קיימת)
df.to_sql('Protocol2Definition', engine, if_exists='replace', index=False)
print("Data has been inserted into Protocol2Definition.")
