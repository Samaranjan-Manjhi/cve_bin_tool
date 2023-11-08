import sqlite3

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
        for row in data:
            print(row)
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
        for row in data:
            print(row)
    else:
        print("No data found for the specified CVE number.")

    conn.close()

# Ask the user for the database path
database_path = "/home/escan/aaaa/cvebintool/cve.db"

# Ask the user to choose between searching by product or CVE number
choice = input("Enter '1' to search by product or '2' to search by CVE number: ")

if choice == '1':
    product_name = input("Enter the product name: ")
    retrieve_data_by_product(database_path, product_name)
elif choice == '2':
    cve_number = input("Enter the CVE number: ")
    retrieve_data_by_cve_number(database_path, cve_number)
else:
    print("Invalid choice. Please enter '1' or '2' to select the search type.")

