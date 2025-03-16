#!/usr/bin/env python3
"""
סקריפט זה מתחבר למסד נתונים MySQL ויוצר טבלה בשם 'ProtocolSizesAndType'
עם העמודות:
  - name       : שם השדה (VARCHAR)
  - size       : גודל השדה (INT) – עבור שדות קבועים, מספר הבתים; עבור שדות דינמיים, 0.
  - type       : סוג הנתונים של השדה (VARCHAR) (למשל, 'int', 'char')
  - size_field : שם השדה שמגדיר את גודל השדה הדינמי (VARCHAR), או NULL עבור שדות קבועים.

הגדרת הפרוטוקול החדש היא:
  1. proto_id       : 4 בתים, char, קבוע (הערך הוא "PTCL").
  2. version        : 1 בית, int, קבוע.
  3. msg_type       : 1 בית, char, קבוע (ערכים אפשריים: 'D' (Data), 'C' (Command), 'E' (Error)).
  4. session_id     : 4 בתים, int, קבוע.
  5. seq_num        : 4 בתים, int, קבוע.
  6. timestamp      : 8 בתים, int, קבוע (זמן נוכחי במילישניות, לפי Unix epoch).
  7. payload_length : 4 בתים, int, קבוע.
  8. message_data   : שדה בעל אורך דינמי, char, בגודל 0 (משתנה) כאשר גודלו מוגדר על ידי 'payload_length'.
"""

import pymysql

# פרמטרי החיבור למסד הנתונים (יש להתאים לפי הצורך)
DB_HOST = 'localhost'
DB_USER = 'root'
DB_PASSWORD = 'admin'
DB_NAME = 'project'

connection = pymysql.connect(
    host=DB_HOST,
    user=DB_USER,
    password=DB_PASSWORD,
    db=DB_NAME,
    charset='utf8mb4',
    cursorclass=pymysql.cursors.DictCursor
)

try:
    with connection.cursor() as cursor:
        create_table_query = """
        CREATE TABLE IF NOT EXISTS ProtocolSizesAndType (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            size INT NOT NULL,
            type VARCHAR(50) NOT NULL,
            size_field VARCHAR(255) DEFAULT NULL
        );
        """
        cursor.execute(create_table_query)
        print("Table 'ProtocolSizesAndType' created (if it did not exist).")
        
        # ניקוי הנתונים הקיימים בטבלה (אם יש)
        cursor.execute("DELETE FROM ProtocolSizesAndType;")
        
        # הכנסת הגדרת הפרוטוקול החדש
        insert_query = """
        INSERT INTO ProtocolSizesAndType (name, size, type, size_field) VALUES
        ('proto_id', 4, 'char', NULL),
        ('version', 1, 'int', NULL),
        ('msg_type', 1, 'char', NULL),
        ('session_id', 4, 'int', NULL),
        ('seq_num', 4, 'int', NULL),
        ('timestamp', 8, 'int', NULL),
        ('payload_length', 4, 'int', NULL),
        ('message_data', 0, 'char', 'payload_length');
        """
        cursor.execute(insert_query)
        connection.commit()
        print("Protocol definition inserted into 'ProtocolSizesAndType'.")
finally:
    connection.close()
