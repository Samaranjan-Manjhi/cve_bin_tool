import asyncio
import datetime
import os
import sqlite3
import gzip
import hashlib
import aiohttp
import json
import re

class CVEDataProcessor:
    def __init__(self, database_file="/home/escan/aaaa/cvebintool/nvd.db"):
        self.connection = None
        self.database_file = database_file
        self.cachedir = "/home/escan/181023/data_sounce/nvd"
        self.FEED = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
        self.META_LINK = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"
        self.META_REGEX = re.compile(r'nvdcve-1.1-[\d]+\.json\.gz')

    async def nist_scrape(self, session):
        async with session.get(self.FEED) as response:
            page = await response.text()
            json_meta_links = self.META_REGEX.findall(page)
            return dict(
                await asyncio.gather(
                    *[self.getmeta(session, f"{self.META_LINK}{meta_url}") for meta_url in json_meta_links]
                )
            )

    async def cache_update(self, session, url, sha, chunk_size=16 * 1024):
        filename = url.split("/")[-1]
        filepath = os.path.join(self.cachedir, filename)

        if not filepath.startswith(self.cachedir):
            raise Exception("Attempted to write outside cachedir.")

        if os.path.isfile(filepath):
            sha = sha.upper()
            calculate = hashlib.sha256()
            async with gzip.open(filepath, "rb") as f:
                chunk = await f.read(chunk_size)
                while chunk:
                    calculate.update(chunk)
                    chunk = await f.read(chunk_size)

            gotsha = calculate.hexdigest().upper()

            if gotsha != sha:
                os.unlink(filepath)
                print(f"SHA mismatch for {filename} (have: {gotsha}, want: {sha})")
            else:
                print(f"Correct SHA for {filename}")
                return

        print(f"Updating CVE cache for {filename}")
        async with session.get(url) as response:
            gzip_data = await response.read()
        with gzip.open(filepath, "wb") as file:
            file.write(gzip_data)

        json_data = gzip.decompress(gzip_data)
        gotsha = hashlib.sha256(json_data).hexdigest().upper()

        if gotsha != sha:
            os.unlink(filepath)
            print(f"SHA mismatch for {filename} (have: {gotsha}, want: {sha})")

    async def refresh(self):
        if not os.path.isfile(self.database_file) or (
            datetime.datetime.today()
            - datetime.datetime.fromtimestamp(os.path.getmtime(self.database_file))
        ) > datetime.timedelta(hours=24):
            async with aiohttp.ClientSession() as session:
                data = await self.nist_scrape(session)
                for url, sha in data.items():
                    await self.cache_update(session, url, sha)

    async def getmeta(self, session, meta_url):
        async with session.get(meta_url) as response:
            meta = await response.text()
            sha = re.search(r"sha256:(\w+)", meta).group(1)
            return (meta_url, sha)

    def init_database(self):
        if not os.path.exists(self.cachedir):
            os.makedirs(self.cachedir)
        self.db_open()
        cursor = self.connection.cursor()
        cve_data_create = """
        CREATE TABLE IF NOT EXISTS cve_severity (
            cve_number TEXT PRIMARY KEY,
            severity TEXT,
            description TEXT,
            score INTEGER,
            cvss_version INTEGER
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
            year INTEGER  -- Add a new 'year' column
        )
        """
        index_range = "CREATE INDEX IF NOT EXISTS product_index ON cve_range (cve_number, vendor, product)"
        cursor.execute(cve_data_create)
        cursor.execute(version_range_create)
        cursor.execute(index_range)
        self.connection.commit()

    def db_open(self):
        if self.connection is None:
            self.connection = sqlite3.connect(self.database_file)

    def db_close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    async def download_cve_data(self, session, year):
        url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
        local_path = os.path.join(self.cachedir, f"nvdcve-1.1-{year}.json.gz")
        
        if not os.path.isfile(local_path):
            async with session.get(url) as response:
                if response.status == 200:
                    with open(local_path, 'wb') as f:
                        while True:
                            chunk = await response.content.read(1024)
                            if not chunk:
                                break
                            f.write(chunk)

    async def download_cve_data_range(self, start_year, end_year):
        async with aiohttp.ClientSession() as session:
            await asyncio.gather(
                *[self.download_cve_data(session, year) for year in range(start_year, end_year + 1)]
            )

    def extract_severity_info(self, cve_item):
        # Replace this with your actual logic to extract severity information
        severity = cve_item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity", "Unknown")
        description = cve_item.get("description", "No description available")
        score = cve_item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore", 0)
        cvss_version = 3  # You can modify this as needed
        return severity, description, score, cvss_version

    def insert_cve_data(self, json_data, year):
        self.db_open()
        cursor = self.connection.cursor()

        for cve_item in json_data["CVE_Items"]:
            cve_number = cve_item["cve"]["CVE_data_meta"]["ID"]

            # Check if the CVE entry already exists in the database
            cursor.execute("SELECT 1 FROM cve_severity WHERE cve_number = ?", (cve_number,))
            existing_entry = cursor.fetchone()

            if not existing_entry:
                severity, description, score, cvss_version = self.extract_severity_info(cve_item)
                self.insert_cve_severity(cursor, cve_number, severity, description, score, cvss_version)
                self.insert_cve_range(cursor, cve_number, cve_item.get("configurations", {}), year)

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

    def insert_cve_range(self, cursor, cve_number, configurations, year):
        if "nodes" in configurations:
            for node in configurations["nodes"]:
                self.insert_cve_range_node(cursor, cve_number, node, year)
                if "children" in node:
                    for child in node["children"]:
                        self.insert_cve_range_node(cursor, cve_number, child, year)

    def insert_cve_range_node(self, cursor, cve_number, node, year):
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
                self.insert_cve_range_info(cursor, cve_number, vendor, product, version, **version_info, year=year)

    def insert_cve_range_info(self, cursor, cve_number, vendor, product, version, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding, year):
        insert_query = """
        INSERT OR REPLACE INTO cve_range (
            cve_number,
            vendor,
            product,
            version,
            versionStartIncluding,
            versionStartExcluding,
            versionEndIncluding,
            versionEndExcluding,
            year
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        cursor.execute(insert_query, (cve_number, vendor, product, version, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding, year))

if __name__ == "__main__":
    cve_data_processor = CVEDataProcessor()

    # Initialize the database tables
    cve_data_processor.init_database()

    # Update the CVE data
    asyncio.run(cve_data_processor.refresh())

    # Download and insert CVE data for the specified range of years (2002 to current year)
    start_year = 2002
    end_year = datetime.datetime.now().year

    async def download_and_insert_data():
        async with aiohttp.ClientSession() as session:
            for year in range(start_year, end_year + 1):
                await cve_data_processor.download_cve_data(session, year)
                local_path = os.path.join(cve_data_processor.cachedir, f"nvdcve-1.1-{year}.json.gz")
                with gzip.open(local_path, 'rb') as file:
                    json_data = json.load(file)
                    cve_data_processor.insert_cve_data(json_data, year)

    asyncio.run(download_and_insert_data())


