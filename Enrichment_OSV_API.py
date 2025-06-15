import os
import requests
import psycopg2
from dotenv import load_dotenv
from time import sleep

# Load API key from .env
load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")

# DB config
DB_NAME = "docker_vuln_db"
DB_USER = "docker_scanner"
DB_PASSWORD = "docker123"
DB_HOST = "localhost"

def enrich_with_osv():
    conn = psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST
    )
    cur = conn.cursor()

    # Get distinct CVEs that are not enriched yet
    cur.execute("""
        SELECT DISTINCT vulnerability_id 
        FROM docker_vulnerabilities_flat 
        WHERE osv_summary IS NULL OR osv_summary = '';
    """)
    cves = [row[0] for row in cur.fetchall()]

    print(f"🔍 Found {len(cves)} unenriched CVEs.")

    for cve in cves:
        url = f"https://api.osv.dev/v1/vulns/{cve}"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                print(f"❌ Failed to fetch {cve} - Status: {response.status_code}")
                continue

            data = response.json()

            summary = data.get("details", "")
            modified = data.get("modified")
            published = data.get("published")
            references = [ref.get("url") for ref in data.get("references", [])]

            vendor_fix_url = ""
            for ref in data.get("references", []):
                if ref.get("type") in ["ADVISORY", "FIX"]:
                    vendor_fix_url = ref.get("url")
                    break

            patch_date = None
            fixed_versions = []
            for affected in data.get("affected", []):
                for range_item in affected.get("ranges", []):
                    for event in range_item.get("events", []):
                        if "fixed" in event:
                            fixed_versions.append(event["fixed"])
                        if "introduced" in event and patch_date is None:
                            patch_date = event.get("fixed", None)

            cur.execute("""
                UPDATE docker_vulnerabilities_flat
                SET
                    osv_summary = %s,
                    osv_references = %s,
                    vendor_fix_url = %s,
                    fixed_versions = %s,
                    nvd_last_modified = %s
                WHERE vulnerability_id = %s;
            """, (
                summary,
                ", ".join(references),
                vendor_fix_url,
                patch_date,
                ", ".join(fixed_versions),
                modified,
                cve
            ))

            print(f"✅ Enriched {cve}")

        except Exception as e:
            print(f"⚠️ Error processing {cve}: {e}")
            continue

    conn.commit()
    cur.close()
    conn.close()
    print("🚀 Enrichment complete.")

if __name__ == "__main__":
    enrich_with_osv()
