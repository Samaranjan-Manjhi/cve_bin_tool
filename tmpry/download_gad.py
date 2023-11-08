import os
import json
from pathlib import Path
import aiohttp
import asyncio

class GAD_Source:
    def __init__(self):
        self.cachedir = "/home/escan/181023/data_source/gad"  # Specify your cache directory here
        self.gad_url = "https://gitlab.com/gitlab-org/security-products/gemnasium-db/-/archive/master/gemnasium-db-master.zip"
        self.session = None

    async def get_req(self, url, session):
        async with await session.get(url) as r:
            if r.status == 200:
                return await r.read()
            return None

    async def fetch_gad_cves(self):
        if not os.path.exists(self.cachedir):
            os.makedirs(self.cachedir)

        connector = aiohttp.TCPConnector(limit_per_host=10)
        self.session = aiohttp.ClientSession(connector=connector)

        try:
            content = await self.get_req(self.gad_url, self.session)
            if content:
                with open(os.path.join(self.cachedir, "gad_cve.json"), 'wb') as f:
                    f.write(content)
                print("GAD CVE data downloaded and stored.")
            else:
                print("Failed to download GAD CVE data.")
        except Exception as e:
            print(f"Error: {e}")

        if self.session:
            await self.session.close()

async def main():
    gad_source = GAD_Source()
    await gad_source.fetch_gad_cves()

if __name__ == "__main__":
    asyncio.run(main())

