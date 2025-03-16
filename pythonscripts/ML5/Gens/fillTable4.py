# populate_mysql_protocol4_fixed.py

import pandas as pd
from sqlalchemy import create_engine

# עדכן את פרטי החיבור למסד הנתונים
DB_USER = 'root'
DB_PASSWORD = 'admin'
DB_HOST = 'localhost'
DB_PORT = '3306'
DB_NAME = 'project'

# יצירת engine
engine = create_engine(f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}')

# הגדרת הנתונים לטבלת Protocol4Definition (תיקון הגדלים)
data = {
    'name': ['sync', 'id', 'type', 'length', 'payload', 'crc', 'flag'],
    'size': [1, 4, 4, 4, 0, 4, 1],  # תיקון הגדלים
    'type': ['bool', 'int', 'char', 'int', 'char', 'int', 'bool']
}

df = pd.DataFrame(data)
print("Inserting the following data into Protocol4Definition:")
print(df)

# הכנסה לטבלה (אם הטבלה קיימת, היא תוחלף)
df.to_sql('Protocol4Definition', engine, if_exists='replace', index=False)
print("Data has been inserted into Protocol4Definition.")
