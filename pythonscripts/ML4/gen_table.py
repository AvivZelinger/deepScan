#!/usr/bin/env python3
"""
This script connects to a MySQL database and creates a table named 'Protocol3Definition'
with the following columns:
  - name       : field name (VARCHAR)
  - size       : field size (INT) – for fixed fields, set to the number of bytes; for dynamic fields, use 0.
  - type       : field data type (VARCHAR) (e.g., 'int', 'char')
  - size_field : the name of the field that defines the dynamic field’s size (VARCHAR), or NULL for fixed fields.

The protocol definition in this example is:
  1. id       : 4 bytes, int, fixed.
  2. flag     : 1 byte, char, fixed.
  3. length   : 4 bytes, int, fixed.
  4. message  : dynamic-length, char, size=0, size_field = 'length'.
  5. end_flag : 1 byte, char, fixed.
  6. checksum : 4 bytes, int, fixed.
"""

import pymysql

# Database connection parameters (adjust as needed)
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
        
        # Clear any existing data in the table
        cursor.execute("DELETE FROM ProtocolSizesAndType;")
        
        # Insert protocol definition rows
        insert_query = """
        INSERT INTO ProtocolSizesAndType (name, size, type, size_field) VALUES
        ('id', 4, 'int', NULL),
        ('flag', 1, 'char', NULL),
        ('length', 4, 'int', NULL),
        ('message', 0, 'char', 'length'),
        ('end_flag', 1, 'char', NULL),
        ('checksum', 4, 'int', NULL);
        """
        cursor.execute(insert_query)
        connection.commit()
        print("Protocol definition inserted into 'ProtocolSizesAndType'.")
finally:
    connection.close()
