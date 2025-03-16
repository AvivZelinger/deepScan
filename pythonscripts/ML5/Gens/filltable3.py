# populate_mysql_protocol3.py

import pandas as pd
from sqlalchemy import create_engine

# החלף את הפרטים בהתאם למערכת שלך
DB_USER = 'root'
DB_PASSWORD = 'admin'
DB_HOST = 'localhost'
DB_PORT = '3306'
DB_NAME = 'project'

# יצירת engine
engine = create_engine(f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}')

# הגדרת הנתונים לטבלת Protocol3Definition
# בשיטה זו אין שימוש בעמודת length_field – אם גודל=0, נדגים שמדובר בשדה דינמי (נתונים לדוגמה: data)
data = {
    'name': [
        'start_flag', 'msg_id', 'command', 
        'data_length', 'data', 'end_flag'
    ],
    'size': [
        1, 4, 8,
        2, 0, 1  # כאן 'data' מוגדר כ-0 (דינמי)
    ],
    'type': [
        'bool', 'int', 'char',
        'int', 'char', 'bool'
    ]
}

df = pd.DataFrame(data)
print("Inserting the following data into Protocol3Definition:")
print(df)

# הכנסת הנתונים לטבלה (אם קיימת, מחליפים אותה)
df.to_sql('Protocol3Definition', engine, if_exists='replace', index=False)
print("Data has been inserted into Protocol3Definition.")
