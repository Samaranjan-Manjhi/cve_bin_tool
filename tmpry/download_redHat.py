import os
import json
from pathlib import Path
import aiohttp
import asyncio

class REDHAT_Source:
    def __init__(self):
        self.cachedir = "/home/escan/181023/data_source/redhat"  # Specify your cache directory here
        self.redhat_url = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
        self.session = None

    async def get_req(self, url, session):
        async with await session.get(url) as r:
            if r.status == 200:
                return await r.read()
            return None

    async def fetch_redhat_cves(self):
        if not os.path.exists(self.cachedir):
            os.makedirs(self.cachedir)

        connector = aiohttp.TCPConnector(limit_per_host=10)
        self.session = aiohttp.ClientSession(connector=connector)

        try:
            content = await self.get_req(self.redhat_url, self.session)
            if content:
                with open(os.path.join(self.cachedir, "redhat_cve.json"), 'wb') as f:
                    f.write(content)
                print("RedHat CVE data downloaded and stored.")
            else:
                print("Failed to download RedHat CVE data.")
        except Exception as e:
            print(f"Error: {e}")

        if self.session:
            await self.session.close()

async def main():
    redhat_source = REDHAT_Source()
    await redhat_source.fetch_redhat_cves()

if __name__ == "__main__":
    asyncio.run(main())

