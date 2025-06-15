from fastapi import FastAPI, HTTPException
from database import get_connection
from queries import get_vuln_by_id
from queries import get_vulns_by_image_and_tag

app = FastAPI(title="Vulnerability API", version="1.0")

@app.get("/vuln/{vuln_id}")
def read_vuln(vuln_id: str):
    conn = get_connection()
    try:
        vuln = get_vuln_by_id(conn, vuln_id)
        if vuln is None:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        return vuln
    finally:
        conn.close()

"""@app.get("/vulns/severity/{severity}")
def list_by_severity(severity: str):
    conn = get_connection()
    try:
        result = get_vulns_by_severity(conn, severity.upper())
        return result
    finally:
        conn.close()"""
        
@app.get("/vulns/image/{image_name}/{tag}")
def list_by_image_and_tag(image_name: str, tag: str):
    conn = get_connection()
    result = get_vulns_by_image_and_tag(conn, image_name, tag)
    conn.close()
    return result
