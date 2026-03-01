import json
import os
from pathlib import Path

import requests
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone

load_dotenv()

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_cves_by_date(start_date: str, end_date: str) -> dict:
    headers = {}
    api_key = os.getenv("NVD_API_KEY")

    if api_key:
        headers["apiKey"] = api_key

    params = {
        "pubStartDate": start_date,
        "pubEndDate": end_date,
        "resultsPerPage": 2000,
    }

    r = requests.get(NVD_URL, params=params, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()

def main():
    now = datetime.now(timezone.utc)
    seven_days_ago = now - timedelta(days=7)

    start_date = seven_days_ago.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_date = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    start_date_str = seven_days_ago.strftime("%Y-%m-%d")
    end_date_str = now.strftime("%Y-%m-%d")

    data = fetch_cves_by_date(start_date, end_date)

    out_dir = Path("data") / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)

    filename = f"{start_date_str}_to_{end_date_str}.json".replace(":", "-")
    out_path = out_dir / filename

    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Saved: {out_path.resolve()}")

if __name__ == "__main__":
    main()