import asyncio
import os
import sqlite3
from aiohttp import ClientSession, TCPConnector
import datetime

class NVD_Source:
    def __init__(self):
        self.cache_dir_path = "/home/escan/181023/"
        self.cache_dir_name = "nvd"
        self.cachedir = os.path.join(self.cache_dir_path, self.cache_dir_name)
        self.session = None
        self.database_path = "/home/escan/aaaa/cvebintool/nvd.db"

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

if __name__ == "__main__":
    downloader = NVD_Source()

    # Create a connection to the SQLite database
    conn = sqlite3.connect(downloader.database_path)

    # Create a cursor to execute SQL commands
    cursor = conn.cursor()

    # Execute table creation SQL commands
    table_schemas = downloader.table_schemas()
    for schema in table_schemas:
        cursor.execute(schema)

    # Commit changes and close the connection
    conn.commit()
    conn.close()

    # Run the download_cve_data function
    asyncio.run(downloader.download_cve_data())

