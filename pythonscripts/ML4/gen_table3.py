#!/usr/bin/env python3
"""
This script connects to a MySQL database and creates a table named 'ProtocolSizesAndType'
with the following columns:
  - name       : Field name (VARCHAR)
  - size       : Field size in bytes (INT) – for fixed-size fields; for dynamic fields, use 0.
  - type       : Data type (VARCHAR) (e.g., 'int', 'char', 'bit')
  - size_field : The field name that determines the size of a dynamic field, or NULL for fixed fields.

The new protocol definition is:
  1. signature       : 4 bytes, char, constant ('NPRT')
  2. version         : 1 byte, int, constant
  3. flags           : 1 byte, bit (bitfield)
  4. command         : 1 byte, char
  5. session_id      : 4 bytes, int
  6. msg_id          : 4 bytes, int
  7. timestamp       : 8 bytes, int
  8. payload_size    : 4 bytes, int
  9. message         : Dynamic field, char, with length defined by 'payload_size'
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
        
        # Insert the new protocol definition
        insert_query = """
        INSERT INTO ProtocolSizesAndType (name, size, type, size_field) VALUES
        ('signature', 4, 'char', NULL),
        ('version', 1, 'int', NULL),
        ('flags', 1, 'bitfield', NULL),
        ('command', 1, 'char', NULL),
        ('session_id', 4, 'int', NULL),
        ('msg_id', 4, 'int', NULL),
        ('timestamp', 8, 'int', NULL),
        ('payload_size', 4, 'int', NULL),
        ('message', 0, 'char', 'payload_size');
        """
        cursor.execute(insert_query)
        connection.commit()
        print("Protocol definition inserted into 'ProtocolSizesAndType'.")
finally:
    connection.close()
