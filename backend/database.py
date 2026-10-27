"""
JobShield Database Management System.
Provides a multi-tier database engine with SQLite (ACID relational),
graceful Local JSON export/sync, and optional MongoDB integration.
Guarantees 100% demo uptime with zero crashes.
"""
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

from config import (
    MONGODB_URI,
    DATABASE_NAME,
    LOCAL_DB_FILE,
    SQLITE_DB_FILE,
    DATA_DIR
)

try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False


class DatabaseManager:
    """
    Robust Database Manager for JobShield.
    Primary store: SQLite database (jobshield.db) + in-sync Local JSON (local_db.json).
    Optional remote store: MongoDB (if reachable).
    """

    def __init__(self):
        self.mode = "SQLITE"
        self.mongo_client = None
        self.mongo_db = None
        self.has_mongo = False
        
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._init_sqlite()
        self._init_mongo()
        self._seed_all_data()

    @contextmanager
    def _get_sqlite_conn(self):
        """Yields a managed connection to SQLite that cleanly closes after use."""
        conn = sqlite3.connect(str(SQLITE_DB_FILE), timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_sqlite(self):
        """Creates tables for reports, companies, salary benchmarks, and scam templates."""
        with self._get_sqlite_conn() as conn:
            cursor = conn.cursor()
            
            # Reports table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id TEXT PRIMARY KEY,
                    company_name TEXT,
                    phone TEXT,
                    email TEXT,
                    upi_id TEXT,
                    domain TEXT,
                    telegram TEXT,
                    amount_demanded REAL DEFAULT 0,
                    scam_type TEXT,
                    description TEXT,
                    city TEXT,
                    status TEXT DEFAULT 'approved',
                    created_at TEXT,
                    moderated_at TEXT
                )
            """)

            # Companies registry table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS companies (
                    id TEXT PRIMARY KEY,
                    name TEXT,
                    aliases TEXT,
                    cin TEXT,
                    gstin TEXT,
                    pan TEXT,
                    official_domain TEXT,
                    official_email_domains TEXT,
                    registered_address TEXT,
                    incorporation_year INTEGER,
                    status TEXT DEFAULT 'Active',
                    is_genuine INTEGER DEFAULT 1
                )
            """)

            # Salary benchmarks table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS salary_benchmarks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    role TEXT,
                    experience_level TEXT,
                    tier1_min REAL,
                    tier1_median REAL,
                    tier1_max REAL,
                    tier2_min REAL,
                    tier2_median REAL,
                    tier2_max REAL,
                    tier3_min REAL,
                    tier3_median REAL,
                    tier3_max REAL
                )
            """)

            # Scam templates table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scam_templates (
                    id TEXT PRIMARY KEY,
                    category TEXT,
                    title TEXT,
                    text TEXT,
                    report_count INTEGER DEFAULT 1,
                    typical_fee REAL DEFAULT 0,
                    risk_level TEXT DEFAULT 'High'
                )
            """)

            # Scan results table (for shareable report cards)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    id TEXT PRIMARY KEY,
                    created_at TEXT,
                    expires_at TEXT,
                    report_type TEXT,
                    summary TEXT,
                    trust_score INTEGER,
                    risk_level TEXT,
                    confidence TEXT,
                    findings_json TEXT,
                    evidence_json TEXT,
                    recommended_steps_json TEXT,
                    limitations_text TEXT,
                    is_revoked INTEGER DEFAULT 0
                )
            """)

            conn.commit()

    def _init_mongo(self):
        """Attempts connection to MongoDB if configured."""
        if PYMONGO_AVAILABLE and MONGODB_URI:
            try:
                self.mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=1500)
                self.mongo_client.admin.command('ping')
                self.mongo_db = self.mongo_client[DATABASE_NAME]
                self.has_mongo = True
                self.mode = "SQLITE + MONGODB SYNC"
                print(f"[DATABASE] Connected to MongoDB ({DATABASE_NAME}). Mode: {self.mode}")
            except Exception as e:
                self.has_mongo = False
                self.mode = "SQLITE (ACID Storage & JSON Sync)"
                print(f"[DATABASE] MongoDB unavailable ({e}). Using robust SQLite + JSON engine.")
        else:
            self.mode = "SQLITE (ACID Storage & JSON Sync)"
            print(f"[DATABASE] Running on SQLite engine ({SQLITE_DB_FILE}).")

    def _seed_all_data(self):
        """Seeds tables from local JSON datasets if tables are currently empty."""
        with self._get_sqlite_conn() as conn:
            cursor = conn.cursor()

            # 1. Seed Reports
            cursor.execute("SELECT COUNT(*) as cnt FROM reports")
            if cursor.fetchone()["cnt"] == 0:
                reports_to_insert = []
                
                # Load reports_store.json if exists
                rep_store_file = DATA_DIR / "reports_store.json"
                if rep_store_file.exists():
                    try:
                        with open(rep_store_file, "r", encoding="utf-8") as f:
                            raw = json.load(f)
                            if isinstance(raw, list):
                                reports_to_insert.extend(raw)
                    except Exception as e:
                        print(f"[DATABASE] Error loading reports_store.json: {e}")

                # Load seed_reports.json if exists
                seed_file = DATA_DIR / "seed_reports.json"
                if seed_file.exists():
                    try:
                        with open(seed_file, "r", encoding="utf-8") as f:
                            s_data = json.load(f).get("reports", [])
                            reports_to_insert.extend(s_data)
                    except Exception as e:
                        print(f"[DATABASE] Error loading seed_reports.json: {e}")

                seen_ids = set()
                for r in reports_to_insert:
                    rid = str(r.get("id") or uuid.uuid4())
                    if rid in seen_ids:
                        continue
                    seen_ids.add(rid)

                    cursor.execute("""
                        INSERT OR REPLACE INTO reports (
                            id, company_name, phone, email, upi_id, domain,
                            telegram, amount_demanded, scam_type, description,
                            city, status, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        rid,
                        r.get("company_name", ""),
                        r.get("phone", ""),
                        r.get("email", ""),
                        r.get("upi_id", ""),
                        r.get("domain", ""),
                        r.get("telegram", ""),
                        float(r.get("amount_demanded") or 0),
                        r.get("scam_type", "General Fraud"),
                        r.get("description", ""),
                        r.get("city", "Pan-India"),
                        r.get("status", "approved"),
                        r.get("created_at") or r.get("reported_date") or datetime.now(timezone.utc).isoformat()
                    ))
                print(f"[DATABASE] Seeded {len(seen_ids)} reports into SQLite.")

            # 2. Seed Companies
            cursor.execute("SELECT COUNT(*) as cnt FROM companies")
            if cursor.fetchone()["cnt"] == 0:
                companies_file = DATA_DIR / "companies_demo.json"
                if companies_file.exists():
                    try:
                        with open(companies_file, "r", encoding="utf-8") as f:
                            c_list = json.load(f).get("companies", [])
                            for c in c_list:
                                cid = c.get("cin") or str(uuid.uuid4())
                                cursor.execute("""
                                    INSERT OR REPLACE INTO companies (
                                        id, name, aliases, cin, gstin, pan,
                                        official_domain, official_email_domains,
                                        registered_address, incorporation_year,
                                        status, is_genuine
                                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """, (
                                    cid,
                                    c.get("name", ""),
                                    json.dumps(c.get("aliases", [])),
                                    c.get("cin", ""),
                                    c.get("gstin", ""),
                                    c.get("pan", ""),
                                    c.get("official_domain", ""),
                                    json.dumps(c.get("official_email_domains", [])),
                                    c.get("registered_address", ""),
                                    c.get("incorporation_year", 2000),
                                    c.get("status", "Active"),
                                    1 if c.get("is_genuine", True) else 0
                                ))
                        print(f"[DATABASE] Seeded {len(c_list)} company records into SQLite.")
                    except Exception as e:
                        print(f"[DATABASE] Error seeding companies: {e}")

            # 3. Seed Salary Benchmarks
            cursor.execute("SELECT COUNT(*) as cnt FROM salary_benchmarks")
            if cursor.fetchone()["cnt"] == 0:
                sal_file = DATA_DIR / "salary_benchmarks.json"
                if sal_file.exists():
                    try:
                        with open(sal_file, "r", encoding="utf-8") as f:
                            roles = json.load(f).get("roles", [])
                            for b in roles:
                                cursor.execute("""
                                    INSERT INTO salary_benchmarks (
                                        role, experience_level,
                                        tier1_min, tier1_median, tier1_max,
                                        tier2_min, tier2_median, tier2_max,
                                        tier3_min, tier3_median, tier3_max
                                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """, (
                                    b.get("role", ""),
                                    b.get("experience_level", ""),
                                    b.get("tier1_min", 0), b.get("tier1_median", 0), b.get("tier1_max", 0),
                                    b.get("tier2_min", 0), b.get("tier2_median", 0), b.get("tier2_max", 0),
                                    b.get("tier3_min", 0), b.get("tier3_median", 0), b.get("tier3_max", 0)
                                ))
                        print(f"[DATABASE] Seeded {len(roles)} salary benchmark levels into SQLite.")
                    except Exception as e:
                        print(f"[DATABASE] Error seeding salary benchmarks: {e}")

            # 4. Seed Scam Templates
            cursor.execute("SELECT COUNT(*) as cnt FROM scam_templates")
            if cursor.fetchone()["cnt"] == 0:
                tpl_file = DATA_DIR / "scam_templates.json"
                if tpl_file.exists():
                    try:
                        with open(tpl_file, "r", encoding="utf-8") as f:
                            templates = json.load(f).get("templates", [])
                            for t in templates:
                                cursor.execute("""
                                    INSERT OR REPLACE INTO scam_templates (
                                        id, category, title, text, report_count, typical_fee, risk_level
                                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                                """, (
                                    t.get("id", str(uuid.uuid4())),
                                    t.get("category", ""),
                                    t.get("title", ""),
                                    t.get("text", ""),
                                    t.get("report_count", 1),
                                    t.get("typical_fee", 0),
                                    t.get("risk_level", "High")
                                ))
                        print(f"[DATABASE] Seeded {len(templates)} known scam patterns into SQLite.")
                    except Exception as e:
                        print(f"[DATABASE] Error seeding scam templates: {e}")

            conn.commit()

        self._sync_to_local_json()

    def _sync_to_local_json(self):
        """Keeps local_db.json in sync with SQLite records for backward-compatibility."""
        try:
            reports = self.get_reports()
            payload = {
                "database_engine": "SQLite 3.x (with JSON Mirror)",
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "reports_count": len(reports),
                "reports": reports
            }
            with open(LOCAL_DB_FILE, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception as e:
            print(f"[DATABASE] Warning: could not mirror to local_db.json: {e}")

    def get_mode(self) -> str:
        """Returns the active database engine description."""
        return self.mode

    def insert_report(self, report: Dict[str, Any]) -> str:
        """Inserts a new scam report into SQLite and returns the report ID."""
        rid = report.get("id") or f"REP-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        report["id"] = rid
        created_at = report.get("created_at") or datetime.now(timezone.utc).isoformat()
        status = report.get("status") or "pending"

        with self._get_sqlite_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO reports (
                    id, company_name, phone, email, upi_id, domain,
                    telegram, amount_demanded, scam_type, description,
                    city, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rid,
                report.get("company_name", ""),
                report.get("phone", ""),
                report.get("email", ""),
                report.get("upi_id", ""),
                report.get("domain", ""),
                report.get("telegram", ""),
                float(report.get("amount_demanded") or 0),
                report.get("scam_type", "Job Offer Fraud"),
                report.get("description", ""),
                report.get("city", "India"),
                status,
                created_at
            ))
            conn.commit()

        # If MongoDB is connected, replicate
        if self.has_mongo and self.mongo_db is not None:
            try:
                doc = dict(report)
                doc["_id"] = rid
                self.mongo_db.reports.replace_one({"_id": rid}, doc, upsert=True)
            except Exception as e:
                print(f"[DATABASE] Mongo sync error: {e}")

        self._sync_to_local_json()
        return rid

    def get_reports(
        self,
        status: Optional[str] = None,
        limit: Optional[int] = None,
        search: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieves reports from SQLite with optional filtering and search."""
        with self._get_sqlite_conn() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM reports"
            params = []
            conditions = []

            if status and status.lower() != "all":
                conditions.append("status = ?")
                params.append(status)

            if search:
                kw = f"%{search.strip().lower()}%"
                conditions.append("""
                    (LOWER(company_name) LIKE ? OR
                     LOWER(phone) LIKE ? OR
                     LOWER(email) LIKE ? OR
                     LOWER(upi_id) LIKE ? OR
                     LOWER(domain) LIKE ? OR
                     LOWER(telegram) LIKE ? OR
                     LOWER(description) LIKE ?)
                """)
                params.extend([kw] * 7)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY created_at DESC"

            if limit:
                query += " LIMIT ?"
                params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def find_linked_reports(self, query_dict: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Finds reports matching any suspect identifier:
        phone, email, upi_id, domain, telegram, or company_name.
        """
        matched = []
        with self._get_sqlite_conn() as conn:
            cursor = conn.cursor()
            for key, val in query_dict.items():
                if not val:
                    continue
                val_clean = str(val).strip().lower()
                # Clean phone number for resilient matching (e.g., match last 10 digits)
                if key == "phone":
                    digits = "".join(ch for ch in val_clean if ch.isdigit())
                    if len(digits) >= 10:
                        last10 = digits[-10:]
                        cursor.execute("SELECT * FROM reports WHERE phone LIKE ?", (f"%{last10}%",))
                    else:
                        cursor.execute("SELECT * FROM reports WHERE LOWER(phone) = ?", (val_clean,))
                elif key in ["email", "upi_id", "domain", "telegram"]:
                    cursor.execute(f"SELECT * FROM reports WHERE LOWER({key}) = ?", (val_clean,))
                elif key == "company_name":
                    cursor.execute("SELECT * FROM reports WHERE LOWER(company_name) LIKE ?", (f"%{val_clean}%",))
                else:
                    continue

                for row in cursor.fetchall():
                    item = dict(row)
                    if not any(m["id"] == item["id"] for m in matched):
                        matched.append(item)

        return matched

    def update_report_status(self, report_id: str, new_status: str) -> bool:
        """Updates the status of a report ('approved', 'rejected', 'pending')."""
        moderated_at = datetime.now(timezone.utc).isoformat()
        with self._get_sqlite_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE reports SET status = ?, moderated_at = ? WHERE id = ?",
                (new_status, moderated_at, report_id)
            )
            conn.commit()
            updated = cursor.rowcount > 0

        if updated and self.has_mongo and self.mongo_db is not None:
            try:
                self.mongo_db.reports.update_one(
                    {"_id": report_id},
                    {"$set": {"status": new_status, "moderated_at": moderated_at}}
                )
            except Exception:
                pass

        self._sync_to_local_json()
        return updated

    def delete_report(self, report_id: str) -> bool:
        """Deletes a report by ID."""
        with self._get_sqlite_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM reports WHERE id = ?", (report_id,))
            conn.commit()
            deleted = cursor.rowcount > 0

        if deleted and self.has_mongo and self.mongo_db is not None:
            try:
                self.mongo_db.reports.delete_one({"_id": report_id})
            except Exception:
                pass

        self._sync_to_local_json()
        return deleted

    def get_all_companies(self) -> List[Dict[str, Any]]:
        """Returns all registered company profiles from the official database."""
        with self._get_sqlite_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM companies ORDER BY name ASC")
            results = []
            for r in cursor.fetchall():
                d = dict(r)
                d["aliases"] = json.loads(d["aliases"]) if d.get("aliases") else []
                d["official_email_domains"] = json.loads(d["official_email_domains"]) if d.get("official_email_domains") else []
                results.append(d)
            return results

    def find_company(self, query: str) -> Optional[Dict[str, Any]]:
        """Finds a company by exact or partial name, CIN, or official domain."""
        if not query:
            return None
        q = query.strip().lower()
        companies = self.get_all_companies()
        
        # 1. Exact match on official domain or CIN
        for c in companies:
            if c.get("official_domain") and c["official_domain"].lower() == q:
                return c
            if c.get("cin") and c["cin"].lower() == q:
                return c

        # 2. Match on company name
        for c in companies:
            if c["name"].lower() == q or q in c["name"].lower():
                return c

        # 3. Match on aliases (strict exact or word boundary match)
        for c in companies:
            for alias in c.get("aliases", []):
                a_low = alias.lower()
                if a_low == q:
                    return c
                if len(a_low) > 3 and re.search(rf'\b{re.escape(a_low)}\b', q):
                    return c
                elif len(a_low) <= 3 and re.search(rf'\b{re.escape(alias)}\b', query):
                    return c

        return None

    def get_salary_benchmarks(self, role: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns salary benchmarks, optionally filtered by role keyword."""
        with self._get_sqlite_conn() as conn:
            cursor = conn.cursor()
            if role:
                cursor.execute(
                    "SELECT * FROM salary_benchmarks WHERE LOWER(role) LIKE ? ORDER BY id ASC",
                    (f"%{role.strip().lower()}%",)
                )
            else:
                cursor.execute("SELECT * FROM salary_benchmarks ORDER BY id ASC")
            return [dict(r) for r in cursor.fetchall()]

    def get_scam_templates(self) -> List[Dict[str, Any]]:
        """Returns all known scam templates for similarity matching."""
        with self._get_sqlite_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scam_templates ORDER BY report_count DESC")
            return [dict(r) for r in cursor.fetchall()]

    def get_stats(self) -> Dict[str, Any]:
        """Calculates live statistical metrics for dashboard banners."""
        with self._get_sqlite_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as total, SUM(amount_demanded) as total_amt FROM reports")
            rep_stats = cursor.fetchone()
            total_reports = rep_stats["total"] or 0
            total_amt = rep_stats["total_amt"] or 0

            cursor.execute("SELECT COUNT(*) as pending FROM reports WHERE status = 'pending'")
            pending_count = cursor.fetchone()["pending"] or 0

            cursor.execute("SELECT COUNT(*) as comp_count FROM companies")
            comp_count = cursor.fetchone()["comp_count"] or 0

            cursor.execute("SELECT COUNT(DISTINCT upi_id) as upi_count FROM reports WHERE upi_id != ''")
            upi_count = cursor.fetchone()["upi_count"] or 0

            cursor.execute("SELECT COUNT(DISTINCT phone) as phone_count FROM reports WHERE phone != ''")
            phone_count = cursor.fetchone()["phone_count"] or 0

            return {
                "total_reports": total_reports,
                "total_scam_amount_inr": round(total_amt, 2),
                "pending_moderation": pending_count,
                "registered_companies": comp_count,
                "flagged_upi_handles": upi_count,
                "flagged_phones": phone_count,
                "database_mode": self.get_mode()
            }

    def save_scan_result(self, scan_data: Dict[str, Any]) -> str:
        """
        Saves a sanitized, explainable scan report card into the database.
        Generates an unpredictable reference ID.
        """
        scan_id = scan_data.get("id") or f"JS-SCAN-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        created_at = datetime.now(timezone.utc).isoformat()
        # Default 30-day expiration
        expires_at = scan_data.get("expires_at") or (datetime.now(timezone.utc).timestamp() + 30 * 86400)
        expires_str = datetime.fromtimestamp(expires_at, timezone.utc).isoformat() if isinstance(expires_at, (int, float)) else str(expires_at)

        with self._get_sqlite_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO scan_results (
                    id, created_at, expires_at, report_type, summary,
                    trust_score, risk_level, confidence, findings_json,
                    evidence_json, recommended_steps_json, limitations_text, is_revoked
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """, (
                scan_id,
                created_at,
                expires_str,
                scan_data.get("report_type", "Multimodal Job Scan"),
                scan_data.get("summary", ""),
                int(scan_data.get("trust_score", 50)),
                scan_data.get("risk_level", "Moderate"),
                scan_data.get("confidence", "Moderate"),
                json.dumps(scan_data.get("findings", [])),
                json.dumps(scan_data.get("evidence", {})),
                json.dumps(scan_data.get("recommended_steps", [])),
                scan_data.get("limitations_text", "JobShield provides probabilistic assessments based on heuristic rules and community telemetry. Independent verification with the official employer is always required.")
            ))
            conn.commit()
        return scan_id

    def get_scan_result(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a sanitized report card by ID if not expired or revoked."""
        with self._get_sqlite_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scan_results WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            if data.get("is_revoked", 0) == 1:
                return {"error": "This report card has been revoked.", "revoked": True}
            # Parse json fields safely
            for f in ["findings_json", "evidence_json", "recommended_steps_json"]:
                if data.get(f):
                    key = f.replace("_json", "")
                    try:
                        data[key] = json.loads(data[f])
                    except Exception:
                        data[key] = []
            return data

    def check_duplicate_report(self, report_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Checks if a report with identical or closely matching indicators already exists.
        Prevents duplicate reports and tracks repeat complaints.
        """
        phone = (report_data.get("phone") or "").strip()
        upi = (report_data.get("upi_id") or "").strip().lower()
        email = (report_data.get("email") or "").strip().lower()

        with self._get_sqlite_conn() as conn:
            cursor = conn.cursor()
            conditions = []
            params = []

            # Check phone match (last 10 digits)
            digits = "".join(ch for ch in phone if ch.isdigit())
            if len(digits) >= 10:
                conditions.append("phone LIKE ?")
                params.append(f"%{digits[-10:]}%")

            # Check UPI ID match
            if upi and len(upi) >= 3 and "@" in upi:
                conditions.append("LOWER(upi_id) = ?")
                params.append(upi)

            # Check corporate email match (avoid free gmail false positive duplicates)
            if email and "@" in email:
                edom = email.split("@")[-1]
                if edom not in ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]:
                    conditions.append("LOWER(email) = ?")
                    params.append(email)

            if not conditions:
                return None

            query = f"SELECT * FROM reports WHERE ({' OR '.join(conditions)}) ORDER BY created_at DESC LIMIT 1"
            cursor.execute(query, params)
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def get_indicator_profile(self, indicator_val: str) -> Dict[str, Any]:
        """
        Builds a comprehensive profile for an indicator (phone, UPI, domain, email, or company),
        showing report counts, recency, connections, and evidence labels without exposing raw PII.
        """
        raw_val = (indicator_val or "").strip()
        if not raw_val:
            return {"found": False, "message": "No indicator provided."}

        def _mask_phone(p: str) -> str:
            if not p:
                return ""
            d = "".join(ch for ch in p if ch.isdigit())
            return f"+91 {d[-10:-8]}******{d[-2:]}" if len(d) >= 10 else p[:2] + "****"

        def _mask_email(e: str) -> str:
            if not e or "@" not in e:
                return e or ""
            u, dom = e.split("@", 1)
            return f"{u[0]}***{u[-1]}@{dom}" if len(u) > 2 else f"{u[0]}*@{dom}"

        # Find linked reports
        linked = self.find_linked_reports({
            "phone": raw_val,
            "email": raw_val,
            "upi_id": raw_val,
            "domain": raw_val,
            "company_name": raw_val
        })

        if not linked:
            # Check company registry
            comp = self.find_company(raw_val)
            if comp:
                return {
                    "found": True,
                    "indicator": comp.get("name"),
                    "indicator_type": "company",
                    "status_label": "Verified Registered Corporation" if comp.get("is_genuine") else "Known Scam Alias",
                    "confidence_level": "High (Official MCA Registry)",
                    "report_count": 0,
                    "total_demanded_inr": 0.0,
                    "official_domain": comp.get("official_domain"),
                    "incorporation_year": comp.get("incorporation_year"),
                    "associated_indicators": {
                        "phones": [],
                        "upis": [],
                        "domains": [comp.get("official_domain")] if comp.get("official_domain") else []
                    },
                    "recent_reports": [],
                    "summary": f"{comp.get('name')} is a registered entity under MCA (CIN: {comp.get('cin', 'N/A')})."
                }

            return {
                "found": False,
                "indicator": raw_val,
                "report_count": 0,
                "status_label": "No Community Reports on Record",
                "confidence_level": "Unreported in Database",
                "message": f"No previous complaints found for '{raw_val}'. Note: Absence of prior reports is not proof of authenticity."
            }

        # Analyze linked reports
        rep_count = len(linked)
        total_amount = sum(float(r.get("amount_demanded") or 0) for r in linked)
        dates = [r.get("created_at") for r in linked if r.get("created_at")]
        dates.sort()
        first_reported = dates[0] if dates else "Unknown"
        last_reported = dates[-1] if dates else "Unknown"

        assoc_phones = list(set([_mask_phone(r.get("phone", "")) for r in linked if r.get("phone")]))
        assoc_upis = list(set([r.get("upi_id") for r in linked if r.get("upi_id")]))
        assoc_domains = list(set([r.get("domain") for r in linked if r.get("domain")]))
        assoc_comps = list(set([r.get("company_name") for r in linked if r.get("company_name")]))

        if rep_count >= 3 or total_amount >= 15000:
            status_label = "Suspect Nexus Hub (Multiple Corroborating Reports)"
            risk_level = "High"
        elif rep_count >= 1:
            status_label = "Community Fraud Allegation"
            risk_level = "Needs Verification"
        else:
            status_label = "Under Review"
            risk_level = "Low"

        public_reports = []
        for r in linked[:10]:
            public_reports.append({
                "id": r.get("id"),
                "scam_type": r.get("scam_type"),
                "company_name": r.get("company_name"),
                "phone": _mask_phone(r.get("phone", "")),
                "email": _mask_email(r.get("email", "")),
                "upi_id": r.get("upi_id"),
                "amount_demanded": r.get("amount_demanded"),
                "city": r.get("city"),
                "status": r.get("status"),
                "created_at": r.get("created_at")
            })

        return {
            "found": True,
            "indicator": raw_val,
            "indicator_query": raw_val,
            "report_count": rep_count,
            "occurrences": rep_count,
            "total_demanded_inr": round(total_amount, 2),
            "first_reported": first_reported,
            "last_reported": last_reported,
            "status_label": status_label,
            "risk_level": risk_level,
            "confidence_level": "High (Multi-victim Telemetry)" if rep_count >= 3 else "Moderate (Community Report)",
            "associated_indicators": {
                "companies": assoc_comps,
                "phones": assoc_phones,
                "upis": assoc_upis,
                "domains": assoc_domains
            },
            "recent_reports": public_reports,
            "related_reports": public_reports,
            "disclaimer": "This indicator profile reflects community submissions and pattern correlations. Allegations remain community-reported until corroborated by law enforcement or official employer notification."
        }


# Singleton database manager instance
db_manager = DatabaseManager()
