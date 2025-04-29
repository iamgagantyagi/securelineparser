import pandas as pd
import psycopg2
import json

# Database connection details - use environment variables exclusively for database connection
DB_HOST = os.environ.get("DB_HOST", "localhost")  # Providing fallback defaults
DB_PORT = os.environ.get("DB_PORT", "5555")
DB_NAME = os.environ.get("DB_NAME", "securitytoolparser")
DB_USER = os.environ.get("DB_USER", "postgres") 
DB_PASSWORD = os.environ.get("DB_PASSWORD", "root")
TABLE_NAME = 'cis_controls_mappings'

json_input_filepath = "config.json"
with open(json_input_filepath, 'r') as json_file:
    input_json = json.load(json_file)

# Database connection details
# DB_HOST = input_json.get("pg_conn_params").get("host")
# DB_PORT = input_json.get("pg_conn_params").get("port")
# DB_NAME = input_json.get("pg_conn_params").get("dbname")
# DB_USER = input_json.get("pg_conn_params").get("user")
# DB_PASSWORD = input_json.get("pg_conn_params").get("password")
# TABLE_NAME = 'cis_controls_mappings'

# Path to your Excel file
EXCEL_FILE = 'CIS_Controls_Mapping_Severity.xlsx'

# Read Excel sheet
data = pd.read_excel(EXCEL_FILE)
mapped_data = data.rename(columns={
    'Control': 'cis_control',
    'Title': 'title',
    'Severity Level': 'severity'
})[['cis_control', 'title', 'severity']]

# Establish connection to PostgreSQL
try:
    connection = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    cursor = connection.cursor()

    # Insert data row by row
    for _, row in mapped_data.iterrows():
        query = f"""
            INSERT INTO {TABLE_NAME} (cis_control, title, severity)
            VALUES (%s, %s, %s)
            ON CONFLICT DO NOTHING;
        """
        cursor.execute(query, tuple(row.values))

    connection.commit()
    print("Data inserted successfully! Duplicate entries skipped.")

except Exception as e:
    print("An error occurred:", e)

finally:
    if connection:
        cursor.close()
        connection.close()
