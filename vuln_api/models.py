from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class Vulnerability(BaseModel):
    vulnerability_id: str
    title: Optional[str]
    severity: str
    cvss_score: Optional[float]
    pkg_name: Optional[str]
    scanned_at: Optional[datetime]
    fixed_version: Optional[str]
    osv_summary: Optional[str]
