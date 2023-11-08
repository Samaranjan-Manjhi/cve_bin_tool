import asyncio
import os
import sqlite3
import json
import gzip
from aiohttp import ClientSession, TCPConnector
import datetime

class NVD_Source:
    def __init__(self):
        self.cache_dir_path = "/home/escan/181023/"
        self.cache_dir_name = "nvd"
        self.cachedir = os.path.join(self.cache_dir_path, self.cache_dir_name)
        self.session = None
        self.database_path = "/home/escan/aaaa/cvebintool/nvd.db"

    INSERT_QUERIES = {
        # Your insert queries here
        "insert_severity": """
       INSERT or REPLACE INTO cve_severity(
            CVE_number,
            severity,
            description,
            score,
            cvss_version,
            cvss_vector,
            data_source,
            last_modified
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        "insert_cve_range": """
        INSERT or REPLACE INTO cve_range(
            cve_number,
            vendor,
            product,
            version,
            versionStartIncluding,
            versionStartExcluding,
            versionEndIncluding,
            versionEndExcluding,
            data_source
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        "insert_exploit": """
        INSERT or REPLACE INTO cve_exploited (
            cve_number,
            product,
            description
            )
            VALUES (?,?,?)
        """,
        "insert_cve_metrics": """
        INSERT or REPLACE INTO cve_metrics (
            cve_number,
            metric_id,
            metric_score,
            metric_field
            )
            VALUES (?, ?, ?, ?)
        """,
        "insert_metrics": """
            INSERT or REPLACE INTO metrics (
                metrics_id,
                metrics_name
            )
            VALUES (?, ?)
        """,
    }

        async def download_cve_data(self):
        if not self.session:
            connector = TCPConnector(limit_per_host=19)
            self.session = ClientSession(connector=connector)

        os.makedirs(self.cachedir, exist_ok=True)

        current_year = datetime.datetime.now().year
        base_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"

        downloaded_files = []

        for year in range(2002, current_year + 1):
            url_to_cve_data = f"{base_url}{year}.json.gz"
            filename = url_to_cve_data.split("/")[-1]
            filepath = os.path.join(self.cachedir, filename)

            if not os.path.exists(filepath):
                async with self.session.get(url_to_cve_data) as response:
                    response.raise_for_status()

                    with open(filepath, "wb") as file:
                        while True:
                            chunk = await response.content.read(1024)
                            if not chunk:
                                break
                            file.write(chunk)

            downloaded_files.append(filepath)

        await self.session.close()
        self.session = None
        downloaded_files.sort()

        for json_file in downloaded_files:
            data_source = json_file  # You may need to extract the data source from the file
            data = self.process_gzip_json_file(json_file)
            self.populate_severity(data.get("cve_severity_data"), data_source)
            self.populate_affected(data.get("cve_range_data"), data_source)
            self.populate_cve_metrics(data.get("cve_severity_data"))
            self.populate_metrics()
            self.populate_exploit_db(data.get("cve_exploited_data"))


    def process_gzip_json_file(self, filepath):
        with gzip.open(filepath, 'rb') as f:
            file_content = f.read().decode('utf-8')
            data = json.loads(file_content)
            return data

    def table_schemas(self):
        cve_data_create = """
        CREATE TABLE IF NOT EXISTS cve_severity (
            cve_number TEXT,
            severity TEXT,
            description TEXT,
            score INTEGER,
            cvss_version INTEGER,
            cvss_vector TEXT,
            data_source TEXT,
            last_modified TIMESTAMP,
            PRIMARY KEY(cve_number, data_source)
        )
        """
        version_range_create = """
        CREATE TABLE IF NOT EXISTS cve_range (
            cve_number TEXT,
            vendor TEXT,
            product TEXT,
            version TEXT,
            versionStartIncluding TEXT,
            versionStartExcluding TEXT,
            versionEndIncluding TEXT,
            versionEndExcluding TEXT,
            data_source TEXT,
            FOREIGN KEY(cve_number, data_source) REFERENCES cve_severity(cve_number, data_source)
        )
        """
        exploit_table_create = """
        CREATE TABLE IF NOT EXISTS cve_exploited (
            cve_number TEXT,
            product TEXT,
            description TEXT,
            PRIMARY KEY(cve_number)
        )
        """
        cve_metrics_table = """
        CREATE TABLE IF NOT EXISTS cve_metrics (
            cve_number TEXT,
            metric_id INTEGER,
            metric_score REAL,
            metric_field TEXT,
            FOREIGN KEY(cve_number) REFERENCES cve_severity(cve_number),
            FOREIGN KEY(metric_id) REFERENCES metrics(metric_id)
        )
        """
        metrics_table = """
        CREATE TABLE IF NOT EXISTS metrics (
            metrics_id  INTEGER,
            metrics_name TEXT,
            PRIMARY KEY(metrics_id)
        )
        """
        return (
            cve_data_create,
            version_range_create,
            exploit_table_create,
            cve_metrics_table,
            metrics_table,
        )

    def populate_severity(self, severity_data, data_source):
        """Populate the database with CVE severities."""
        cursor = self.connection.cursor()
        insert_severity = self.INSERT_QUERIES["insert_severity"]
        del_cve_range = "DELETE from cve_range where cve_number=? and data_source=?"

        # Your code for populating the 'cve_severity' table

    def populate_affected(self, affected_data, data_source):
        """Populate the database with affected versions."""
        cursor = self.connection.cursor()
        insert_cve_range = self.INSERT_QUERIES["insert_cve_range"]

        # Your code for populating the 'cve_range' table

    def populate_cve_metrics(self, severity_data):
        """Adds data into CVE metrics table."""
        cursor = self.connection.cursor()
        insert_cve_metrics = self.INSERT_QUERIES["insert_cve_metrics"]

        # Your code for populating the 'cve_metrics' table

    def populate_metrics(self):
        """Adding data to metric table."""
        cursor = self.connection.cursor()
        insert_metrics = self.INSERT_QUERIES["insert_metrics"]

        # Your code for populating the 'metrics' table

    def populate_exploit_db(self, exploits):
        """Add exploits to the exploits database table."""
        cursor = self.connection.cursor()
        insert_exploit = self.INSERT_QUERIES["insert_exploit"]

        # Your code for populating the 'cve_exploited' table

if __name__ == "__main__":
    downloader = NVD_Source()

    # Create a connection to the SQLite database
    downloader.connection = sqlite3.connect(downloader.database_path)

    # Execute table creation SQL commands
    table_schemas = downloader.table_schemas()
    for schema in table_schemas:
        downloader.connection.execute(schema)

    # Commit changes and close the connection
    downloader.connection.commit()
    downloader.connection.close()

    # Run the download_cve_data function
    asyncio.run(downloader.download_cve_data())

