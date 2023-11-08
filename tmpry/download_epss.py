import os
import json
from pathlib import Path
import aiohttp
import asyncio

class EPSS_Source:
    def __init__(self):
        self.cachedir = "/home/escan/181023/data_source/epss"  # Specify your cache directory here
        self.epss_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
        self.session = None

    async def get_req(self, url, session):
        async with await session.get(url) as r:
            if r.status == 200:
                return await r.read()
            return None

    async def fetch_epss_cves(self):
        if not os.path.exists(self.cachedir):
            os.makedirs(self.cachedir)

        connector = aiohttp.TCPConnector(limit_per_host=10)
        self.session = aiohttp.ClientSession(connector=connector)

        try:
            content = await self.get_req(self.epss_url, self.session)
            if content:
                with open(os.path.join(self.cachedir, "epss_cve.json.gz"), 'wb') as f:
                    f.write(content)
                print("EPSS CVE data downloaded and stored.")
            else:
                print("Failed to download RedHat CVE data.")
        except Exception as e:
            print(f"Error: {e}")

        if self.session:
            await self.session.close()

async def main():
    epss_source = EPSS_Source()
    await epss_source.fetch_epss_cves()

if __name__ == "__main__":
    asyncio.run(main())

