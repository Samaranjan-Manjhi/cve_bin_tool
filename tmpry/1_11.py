import os
import sqlite3
import gzip
import json
import hashlib
from pathlib import Path
import aiohttp
import asyncio
import re
import requests

class CVEDataProcessor:
    def __init__(self, database_file="/home/escan/aaaa/cvebintool/cve1.db"):
        self.connection = None
        self.database_file = database_file
        self.cachedir = "/home/escan/181023/data_source"

    async def refresh(self):
        self.init_database()
        await self.process_all_cache_dirs()
        self.update_exploits()  # Call to update the exploits data

    async def process_all_cache_dirs(self):
        # List of cache directories
        cache_dirs = [
            "/home/escan/181023/data_source/nvd",
            "/home/escan/181023/data_source/epss",
        ]

        for cache_dir in cache_dirs:
            await self.process_cache_dir(cache_dir)

    async def process_cache_dir(self, cache_dir):
        if not os.path.exists(cache_dir):
            print(f"Cache directory does not exist: {cache_dir}")
            return

        for file in Path(cache_dir).glob("*.json.gz"):
            with gzip.open(file, "rb") as gz_file:
                try:
                    json_data = json.load(gz_file)
                except json.decoder.JSONDecodeError:
                    print(f"Error loading JSON data from {file}. Skipping...")
                    continue
                except gzip.BadGzipFile:
                    print(f"Error reading a non-gzip file: {file}. Skipping...")
                    continue
                self.insert_cve_data(json_data)

    def init_database(self):
        self.db_open()
        cursor = self.connection.cursor()
        
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

        index_range = "CREATE INDEX IF NOT EXISTS product_index ON cve_range (cve_number, vendor, product)"
        cursor.execute(cve_data_create)
        cursor.execute(version_range_create)
        cursor.execute(exploit_table_create)  # Move this line inside init_database
        cursor.execute(index_range)

        self.connection.commit()

    def db_open(self):
        if self.connection is None:
            self.connection = sqlite3.connect(self.database_file)

    def update_exploits(self):
        """Get the latest list of vulnerabilities from cisa.gov and add them to the exploits database table."""
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        r = requests.get(url, timeout=300)
        data = r.json()
        cves = data["vulnerabilities"]
        exploit_list = []
        for cve in cves:
            exploit_list.append((cve["cveID"], cve["product"], cve["shortDescription"]))
        self.populate_exploit_db(exploit_list)

    def populate_exploit_db(self, exploit_list):
        self.db_open()
        cursor = self.connection.cursor()

        for exploit in exploit_list:
            cursor.execute(self.insert_exploit, exploit)

        self.connection.commit()

    # SQL query for inserting exploits
    insert_exploit = """
        INSERT OR REPLACE INTO cve_exploited (
            cve_number,
            product,
            description
        )
        VALUES (?, ?, ?)
    """

    def extract_severity_info(self, cve_item):
        # Replace this with your actual logic to extract severity information
        severity = cve_item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity", "Unknown")
        description = cve_item.get("description", "No description available")
        score = cve_item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore", 0)
        cvss_version = 3  # You can modify this as needed
        return severity, description, score, cvss_version

    def insert_cve_data(self, json_data):
        self.db_open()
        cursor = self.connection.cursor()

        for cve_item in json_data.get("CVE_Items", []):
            cve_number = cve_item["cve"]["CVE_data_meta"]["ID"]

            # Check if the CVE entry already exists in the database
            cursor.execute("SELECT 1 FROM cve_severity WHERE cve_number = ?", (cve_number,))
            existing_entry = cursor.fetchone()

            if not existing_entry:
                severity, description, score, cvss_version = self.extract_severity_info(cve_item)
                self.insert_cve_severity(cursor, cve_number, severity, description, score, cvss_version)
                self.insert_cve_range(cursor, cve_number, cve_item.get("configurations", {}))

        self.connection.commit()

    def insert_cve_severity(self, cursor, cve_number, severity, description, score, cvss_version):
        insert_query = """
        INSERT OR REPLACE INTO cve_severity (
            cve_number,
            severity,
            description,
            score,
            cvss_version
        )
        VALUES (?, ?, ?, ?, ?)
        """
        cursor.execute(insert_query, (cve_number, severity, description, score, cvss_version))

    def insert_cve_range(self, cursor, cve_number, configurations):
        if "nodes" in configurations:
            for node in configurations["nodes"]:
                self.insert_cve_range_node(cursor, cve_number, node)
                if "children" in node:
                    for child in node["children"]:
                        self.insert_cve_range_node(cursor, cve_number, child)

    def insert_cve_range_node(self, cursor, cve_number, node):
        if "cpe_match" in node:
            for cpe_match in node["cpe_match"]:
                cpe_split = cpe_match["cpe23Uri"].split(":")
                vendor, product, version = cpe_split[3], cpe_split[4], cpe_split[5]
                version_info = {
                    "versionStartIncluding": cpe_match.get("versionStartIncluding", ""),
                    "versionStartExcluding": cpe_match.get("versionStartExcluding", ""),
                    "versionEndIncluding": cpe_match.get("versionEndIncluding", ""),
                    "versionEndExcluding": cpe_match.get("versionEndExcluding", ""),
                }
                self.insert_cve_range_info(cursor, cve_number, vendor, product, version, **version_info)

    def insert_cve_range_info(self, cursor, cve_number, vendor, product, version, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding):
        insert_query = """
        INSERT OR REPLACE INTO cve_range (
            cve_number,
            vendor,
            product,
            version,
            versionStartIncluding,
            versionStartExcluding,
            versionEndIncluding,
            versionEndExcluding
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        cursor.execute(insert_query, (cve_number, vendor, product, version, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding))

if __name__ == "__main__":
    cve_data_processor = CVEDataProcessor()

    # Initialize the database tables
    cve_data_processor.init_database()

    # Process data from all cache directories and update exploits
    asyncio.run(cve_data_processor.refresh())
