#!/usr/bin/env python3
"""
This script connects to a MySQL database and creates a table named 'BProtocolDefinition'
with the following columns:
  - name       : Field name (VARCHAR)
  - size       : Field size in bytes (INT) – for fixed-size fields; for dynamic fields, use 0.
  - type       : Data type (VARCHAR) (e.g., 'int', 'char', 'bitfield', 'float', 'double')
  - size_field : The field name that determines the size of a dynamic field, or NULL for fixed fields.

The BProtocol is defined as:
  1. header         : 4 bytes, char, constant ('BPRT')
  2. version        : 4 bytes, int
  3. flags1         : 1 byte, bitfield
  4. flags2         : 1 byte, bitfield
  5. temperature    : 4 bytes, float
  6. pressure       : 8 bytes, double
  7. device_id      : 10 bytes, char
  8. message_length : 4 bytes, int
  9. message        : Dynamic field, char, with length defined by 'message_length'
  10. checksum      : 4 bytes, int
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
        CREATE TABLE IF NOT EXISTS ProtocolSizesAndType  (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            size INT NOT NULL,
            type VARCHAR(50) NOT NULL,
            size_field VARCHAR(255) DEFAULT NULL
        );
        """
        cursor.execute(create_table_query)
        print("Table 'ProtocolSizesAndType ' created (if it did not exist).")
        
        # Clear any existing data in the table
        cursor.execute("DELETE FROM ProtocolSizesAndType ;")
        
        # Insert the BProtocol definition
        insert_query = """
        INSERT INTO ProtocolSizesAndType  (name, size, type, size_field) VALUES
        ('header', 4, 'char', NULL),
        ('version', 4, 'int', NULL),
        ('flags1', 1, 'bitfield', NULL),
        ('flags2', 1, 'bitfield', NULL),
        ('temperature', 4, 'float', NULL),
        ('pressure', 8, 'double', NULL),
        ('device_id', 10, 'char', NULL),
        ('message_length', 4, 'int', NULL),
        ('message', 0, 'char', 'message_length'),
        ('checksum', 4, 'int', NULL);
        """
        cursor.execute(insert_query)
        connection.commit()
        print("BProtocol definition inserted into 'ProtocolSizesAndType '.")
finally:
    connection.close()
