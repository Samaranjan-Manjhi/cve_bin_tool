import sqlite3
from prettytable import PrettyTable

# Function to retrieve data based on a specific product
def retrieve_data_by_product(database_path, product_name):
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()

    query = f"""
    SELECT *
    FROM cve_severity
    LEFT JOIN cve_range ON cve_severity.cve_number = cve_range.cve_number
    LEFT JOIN cve_exploited ON cve_severity.cve_number = cve_exploited.cve_number
    WHERE cve_range.product = ?
    """

    cursor.execute(query, (product_name,))
    data = cursor.fetchall()

    if data:
        for table_name in ["cve_severity", "cve_range", "cve_exploited"]:
            table = PrettyTable()
            table.field_names = [table_name]
            column_names = [desc[0] for desc in cursor.description]
            for column in column_names:
                #attribute_values = "|".join(list(set([row[column] for row in data if row[column]])))
                attribute_values = "|".join(list(set([row[column] for row in data if row[list(row).index(column)]])))
                table.add_row([column, attribute_values])

            print(f"\n[{table_name}]")
            print(table)
    else:
        print("No data found for the specified product.")

    conn.close()

# Function to retrieve data based on a specific CVE number
def retrieve_data_by_cve_number(database_path, cve_number):
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()

    query = f"""
    SELECT *
    FROM cve_severity
    LEFT JOIN cve_range ON cve_severity.cve_number = cve_range.cve_number
    LEFT JOIN cve_exploited ON cve_severity.cve_number = cve_exploited.cve_number
    WHERE cve_severity.cve_number = ?
    """

    cursor.execute(query, (cve_number,))
    data = cursor.fetchall()

    if data:
        for table_name in ["cve_severity", "cve_range", "cve_exploited"]:
            table = PrettyTable()
            table.field_names = [table_name]
            column_names = [desc[0] for desc in cursor.description]
            for column in column_names:
                #attribute_values = "|".join(list(set([row[column] for row in data if row[column]])))
                attribute_values = "|".join(list(set([row[column] for row in data if row[list(row).index(column)]])))
                table.add_row([column, attribute_values])

            print(f"\n[{table_name}]")
            print(table)
    else:
        print("No data found for the specified CVE number.")
    conn.close()

# Function to display data for a specific table
def display_data_for_table(database_path, table_name):
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()

    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = cursor.fetchall()
    column_names = [col[1] for col in columns]

    cursor.execute(f"SELECT * FROM {table_name}")
    data = cursor.fetchall()

    if data:
        table = PrettyTable()
        table.field_names = [table_name]
        for column in column_names:
            #attribute_values = "|".join(list(set([row[column] for row in data if row[column]])))
            attribute_values = "|".join(list(set([row[column] for row in data if row[list(row).index(column)]])))
            table.add_row([column, attribute_values])
        print(table)
    else:
        print(f"No data found for table: {table_name}")

    conn.close()

# database path
database_path = "/home/escan/aaaa/cvebintool/cve.db"

# user to choose between searching by product, CVE number, or displaying a specific table
choice = input("Enter '1' to search by product, '2' to search by CVE number, or '3' to display a specific table: ")

if choice == '1':
    product_name = input("Enter the product name: ")
    retrieve_data_by_product(database_path, product_name)
elif choice == '2':
    cve_number = input("Enter the CVE number: ")
    retrieve_data_by_cve_number(database_path, cve_number)
elif choice == '3':
    table_name = input("Enter the table name to display: ")
    display_data_for_table(database_path, table_name)
else:
    print("Invalid choice. Please enter '1', '2', or '3' to select the search type.")

