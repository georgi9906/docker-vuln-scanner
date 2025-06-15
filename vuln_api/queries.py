def get_vuln_by_id(conn, vuln_id):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT vulnerability_id, title, severity, cvss_score, pkg_name,
                   scanned_at, fixed_versions, installed_version,
                   published_date, last_modified_date, nvd_last_modified,
                   description, is_fixed
            FROM docker_vulnerabilities_flat
            WHERE vulnerability_id = %s
        """, (vuln_id,))
        row = cur.fetchone()
        if row:
            keys = [desc[0] for desc in cur.description]
            return dict(zip(keys, row))
        return None

        
def get_vulns_by_image_and_tag(conn, image_name, tag):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT vulnerability_id, title, description, severity, cvss_score, pkg_name, published_date,
                   last_modified_date, installed_version, fixed_versions, scanned_at, is_fixed
            FROM docker_vulnerabilities_flat
            WHERE image_name = %s AND tag = %s
            ORDER BY scanned_at DESC
            LIMIT 100
        """, (image_name, tag))
        rows = cur.fetchall()

        if not rows:
            return {"message": "No vulnerabilities found for this image and tag."}

        # Build list and calculate metrics
        columns = [desc[0] for desc in cur.description]
        vuln_list = [dict(zip(columns, row)) for row in rows]

        high_count = sum(1 for v in vuln_list if v["severity"] == "HIGH")
        critical_count = sum(1 for v in vuln_list if v["severity"] == "CRITICAL")
        total_cvss_score = sum(v["cvss_score"] or 0 for v in vuln_list)

        return {
            "image_name": image_name,
            "tag": tag,
            "total_vulnerabilities": len(vuln_list),
            "high_count": high_count,
            "critical_count": critical_count,
            "risk_cvss_score": total_cvss_score,
            "vulnerabilities": vuln_list
        }
        
        
        
        
        
        
        
        

