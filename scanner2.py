import subprocess
import json
import os
import requests
from datetime import datetime
import psycopg2
from dateutil import parser as dateparser  # pip install python-dateutil

DB_NAME = "docker_vuln_db"
DB_USER = "docker_scanner"
DB_PASSWORD = "docker123"
DB_HOST = "localhost"

REPORTS_DIR = f"Reports_{datetime.now().strftime('%Y-%m-%d')}"
DOCKER_HUB_URL = "https://registry.hub.docker.com/v2/repositories/library"  # <-- ADDED

def ensure_reports_dir():
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)
    return REPORTS_DIR

# <-- ADDED: Function to fetch all tags for a repo
def get_all_tags(repo):
    tags = []
    url = f"{DOCKER_HUB_URL}/{repo}/tags?page_size=100"
    while url:
        response = requests.get(url)
        if response.status_code != 200:
            print(f"❌ Failed to fetch tags for {repo}")
            break
        data = response.json()
        tags.extend([t["name"] for t in data.get("results", [])])
        url = data.get("next")
    return tags

# <-- ADDED: Function to write tags to a file for each repo
def write_tags_to_file(repo, tags):
    filename = f"{repo}_tags.txt"
    with open(filename, "w") as f:
        for tag in tags:
            f.write(f"{tag}\n")

def load_tags_from_txt(filename):
    with open(filename, "r") as file:
        return [line.strip() for line in file if line.strip()]

def run_trivy_scan(repo, tag):
    image_name = f"{repo}:{tag}"
    print(f"🔍 Running Trivy scan for {image_name}...")

    json_report_file = os.path.join(REPORTS_DIR, f"CRITICAL_HIGH_Report_{tag}.json")
    scanned_at = datetime.now()

    try:
        subprocess.run(["docker", "pull", image_name], check=True)

        result = subprocess.run(
            ["docker", "inspect", "--format={{index .RepoDigests 0}}", image_name],
            capture_output=True, text=True, check=True
        )
        digest = result.stdout.strip()
        if not digest:
            print(f"❌ Digest is empty for {image_name}, skipping scan.")
            return

        subprocess.run([
            "trivy", "image", "--severity", "HIGH,CRITICAL",
            "--format", "json", "-o", json_report_file, image_name
        ], check=True)

        with open(json_report_file, "r", encoding="utf-8") as file:
            scan_data = json.load(file)

        updated_at_raw = scan_data.get("Metadata", {}).get("UpdatedAt")
        try:
            updated_at = dateparser.parse(updated_at_raw) if updated_at_raw else scanned_at
        except Exception:
            updated_at = scanned_at

        conn = psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST
        )
        cur = conn.cursor()

        found_cves = set()

        for result in scan_data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                vuln_id = vuln.get("VulnerabilityID")
                found_cves.add(vuln_id)

                # Check if already exists
                cur.execute("""
                    SELECT 1 FROM docker_vulnerabilities_flat
                    WHERE image_name = %s AND tag = %s AND digest = %s
                    AND vulnerability_id = %s
                """, (repo, tag, digest, vuln_id))

                if cur.fetchone():
                    print(f"⚠️ CVE {vuln_id} already in DB for {image_name}")
                    cur.execute("""
                        UPDATE docker_vulnerabilities_flat
                        SET is_fixed = 'No'
                        WHERE image_name = %s AND tag = %s AND digest = %s AND vulnerability_id = %s
                    """, (repo, tag, digest, vuln_id))
                    continue

                cur.execute("""
                    INSERT INTO docker_vulnerabilities_flat (
                        image_name, tag, digest, scanned_at,
                        vulnerability_id, title, description, pkg_name,
                        installed_version, fixed_versions, severity,
                        published_date, last_modified_date, solution,
                        reference_links, cvss_score, trivy_db_updated,
                        is_fixed
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'No');
                """, (
                    repo, tag, digest, scanned_at,
                    vuln_id, vuln.get("Title"), vuln.get("Description"),
                    vuln.get("PkgName"), vuln.get("InstalledVersion"), vuln.get("FixedVersion"),
                    vuln.get("Severity"), vuln.get("PublishedDate"), vuln.get("LastModifiedDate"),
                    vuln.get("PrimaryURL"),
                    ", ".join(vuln.get("References", [])) if vuln.get("References") else None,
                    vuln.get("CVSS", {}).get("nvd", {}).get("V3Score"), updated_at
                ))

        # Mark previously found CVEs that are no longer found as fixed
        cur.execute("""
            UPDATE docker_vulnerabilities_flat
            SET is_fixed = 'Yes'
            WHERE image_name = %s AND tag = %s AND digest = %s
            AND vulnerability_id NOT IN %s
        """, (repo, tag, digest, tuple(found_cves) if found_cves else ('',)))

        conn.commit()
        cur.close()
        conn.close()
        print(f"✅ Scan complete and DB updated for {image_name}.")

    except Exception as e:
        print(f"❌ Error scanning or inserting data for {image_name}: {e}")


def main():
    ensure_reports_dir()
    # Read the list of repositories to scan
    try:
        with open("docker_repos.txt", "r") as f:
            repos = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("❌ docker_repos.txt not found.")
        return

    for repo in repos:
        print(f"📦 Processing repository: {repo}")
        tags = get_all_tags(repo)
        if not tags:
            print(f"⚠️ No tags found for {repo}")
            continue
        write_tags_to_file(repo, tags)  # For traceability

        for tag in tags:
            image_identifier = f"{repo}:{tag}"
            try:
                run_trivy_scan(repo, tag)   # Call scan for each <repo>:<tag>
                subprocess.run(["docker", "rmi", "-f", image_identifier], check=True)
            except subprocess.CalledProcessError as e:
                print(f"⚠️ Failed to process {image_identifier}: {e}")
                # Optionally log this failed tag to a file for further review:
                with open("failed_tags.log", "a") as logf:
                    logf.write(f"{image_identifier} -- {e}\n")
                break
                continue  # Continue to next tag
            except Exception as e:
                print(f"❌ Unexpected error on {image_identifier}: {e}")
                with open("failed_tags.log", "a") as logf:
                    logf.write(f"{image_identifier} -- {e}\n")
                continue  # Continue to next tag



if __name__ == "__main__":
    main()
