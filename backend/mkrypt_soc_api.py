import os
import time
import uuid
import sqlite3
import asyncio
from datetime import datetime, timezone
from typing import Optional
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from google import genai

load_dotenv()

app = FastAPI(title="MKRYPT SOC Portfolio Engine", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Lock to https://beta-mkrypt.vercel.app in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 1. Configuration & Azure Endpoints ---
TENANT_ID = os.getenv("AZURE_TENANT_ID", "").strip()
CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "").strip()
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET", "").strip()
SUB_ID = os.getenv("AZURE_SUBSCRIPTION_ID", "f1dcd00a-9833-4213-aedb-0554245829ee").strip()
RG = os.getenv("AZURE_RESOURCE_GROUP", "SENTINEL-LAB").strip()
WS_NAME = os.getenv("AZURE_WORKSPACE_NAME", "").strip()
WS_ID = os.getenv("AZURE_WORKSPACE_ID", "").strip()
GEMINI_KEY = os.getenv("GEMINI_API_KEY", "").strip()

ARM_BASE = f"https://management.azure.com/subscriptions/{SUB_ID}/resourceGroups/{RG}"
SENTINEL_BASE = (
    f"{ARM_BASE}/providers/Microsoft.OperationalInsights/workspaces/{WS_NAME}"
    f"/providers/Microsoft.SecurityInsights"
)
SENTINEL_API_VER = "2025-09-01"
COMPUTE_API_VER = "2024-07-01"

gemini_client = genai.Client(api_key=GEMINI_KEY)

# --- 2. SQLite Persistence (Analyst Bin, Ticket State, Work Notes) ---
DB_PATH = "mkrypt_soc.db"

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analysts (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                role TEXT NOT NULL,
                email TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ticket_state (
                incident_id TEXT PRIMARY KEY,
                incident_number INTEGER,
                assigned_to TEXT DEFAULT 'T1-Triage-Bin',
                snow_state TEXT DEFAULT 'New',
                ai_analysis TEXT,
                updated_at TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS work_notes (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                author TEXT NOT NULL,
                note TEXT NOT NULL,
                synced_to_sentinel INTEGER DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)
        conn.executemany(
            "INSERT OR IGNORE INTO analysts (id, name, role, email) VALUES (?, ?, ?, ?)",
            [
                ("bin", "T1-Triage-Bin", "Unassigned Queue", "soc-queue@mkrypt.local"),
                ("mohan", "Mohan Krishna", "Senior Threat Detection Engineer", "mohan@mkrypt.local"),
                ("analyst1", "Tier-1 SOC Analyst", "Incident Responder", "t1-analyst@mkrypt.local"),
            ],
        )

init_db()

# --- 3. Dual-Scope Azure OAuth2 Token Cache & KQL Runner ---
_token_cache = {}

async def get_azure_token(scope: str) -> str:
    now = time.time()
    cached = _token_cache.get(scope)
    if cached and cached["expires_at"] > now + 60:
        return cached["token"]

    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": scope,
        "grant_type": "client_credentials",
    }
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, data=data)
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Azure OAuth2 failed: {resp.text}")
        payload = resp.json()
        _token_cache[scope] = {
            "token": payload["access_token"],
            "expires_at": now + int(payload.get("expires_in", 3599)),
        }
        return payload["access_token"]

async def run_kql(query: str, timespan: str = "P7D") -> list[dict]:
    token = await get_azure_token("https://api.loganalytics.io/.default")
    url = f"https://api.loganalytics.io/v1/workspaces/{WS_ID}/query"
    async with httpx.AsyncClient(timeout=25) as client:
        resp = await client.post(
            url,
            headers={"Authorization": f"Bearer {token}"},
            json={"query": query, "timespan": timespan},
        )
        if resp.status_code != 200:
            return [{"error": resp.text}]
        tables = resp.json().get("tables", [])
        if not tables:
            return []
        cols = [c["name"] for c in tables[0]["columns"]]
        return [dict(zip(cols, row)) for row in tables[0]["rows"]]

# --- 4. Health, Topology & VM Power Toggle Endpoints ---
@app.get("/api/health")
async def health_check():
    return {
        "status": "online",
        "resource_group": RG,
        "workspace_configured": bool(WS_NAME and WS_ID),
        "gemini_configured": bool(GEMINI_KEY),
    }

@app.get("/api/lab/topology")
async def get_lab_topology():
    arm_token = await get_azure_token("https://management.azure.com/.default")
    headers = {"Authorization": f"Bearer {arm_token}"}

    async def vm_status(vm_name: str, private_ip: str, os_type: str):
        url = f"{ARM_BASE}/providers/Microsoft.Compute/virtualMachines/{vm_name}/instanceView?api-version={COMPUTE_API_VER}"
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(url, headers=headers)
            power = "Unknown"
            if r.status_code == 200:
                for st in r.json().get("statuses", []):
                    if st.get("code", "").startswith("PowerState/"):
                        power = st["displayStatus"]
            return {"name": vm_name, "os": os_type, "private_ip": private_ip, "power_state": power}

    vms, heartbeat = await asyncio.gather(
        asyncio.gather(
            vm_status("VM-1", "172.16.0.4", "Ubuntu Linux (B2)"),
            vm_status("Win-Victim-01", "172.16.0.5", "Windows Server 2022 (B2als_v2)"),
        ),
        run_kql("Heartbeat | summarize LastSeen=max(TimeGenerated), Category=any(Category) by Computer", "PT24H"),
    )
    return {
        "resource_group": RG,
        "region": "East Asia",
        "virtual_machines": vms,
        "connected_agents_24h": heartbeat,
    }

@app.post("/api/vms/{vm_name}/{action}")
async def control_vm_power(vm_name: str, action: str):
    if vm_name not in {"VM-1", "Win-Victim-01"} or action not in {"start", "deallocate"}:
        raise HTTPException(status_code=400, detail="Use VM-1 or Win-Victim-01 with start or deallocate")
    arm_token = await get_azure_token("https://management.azure.com/.default")
    url = f"{ARM_BASE}/providers/Microsoft.Compute/virtualMachines/{vm_name}/{action}?api-version={COMPUTE_API_VER}"
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(url, headers={"Authorization": f"Bearer {arm_token}"})
        if resp.status_code not in (200, 202):
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
    return {"vm": vm_name, "action": action, "status": "Accepted"}

@app.get("/api/lab/kql-sandbox")
async def get_kql_sandbox():
    return {
        "portal_url": "https://portal.azure.com",
        "username": os.getenv("SOC_VIEWER_UPN"),
        "password": os.getenv("SOC_VIEWER_PASS"),
        "rbac_roles": ["Microsoft Sentinel Reader", "Log Analytics Reader"],
        "sample_queries": [
            {
                "title": "Failed Logon Brute-Force Hunt",
                "kql": "SecurityEvent | where EventID == 4625 | summarize Attempts=count() by TargetUserName, IpAddress, Computer | where Attempts > 3",
            },
            {
                "title": "Linux SSH Failed Logins",
                "kql": "Syslog | where Facility in ('auth','authpriv') and SyslogMessage has 'Failed password' | summarize Failures=count() by Computer, HostIP",
            },
            {
                "title": "All Connected Hosts Heartbeat",
                "kql": "Heartbeat | summarize LastHeartbeat=max(TimeGenerated) by Computer, OSType, Version",
            },
        ],
    }

# --- 5. ServiceNow ITSM Queue, Analyst Bin & Bidirectional Sentinel Sync ---
class AssignRequest(BaseModel):
    analyst_id: str

class WorkNoteRequest(BaseModel):
    author: str
    note: str
    new_status: Optional[str] = None  # Active, Closed, New

@app.get("/api/analysts")
def list_analysts():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute("SELECT * FROM analysts").fetchall()]

@app.get("/api/incidents")
async def list_incidents():
    arm_token = await get_azure_token("https://management.azure.com/.default")
    url = f"{SENTINEL_BASE}/incidents?api-version={SENTINEL_API_VER}&$top=30"
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {arm_token}"})
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)

    items = resp.json().get("value", [])
    results = []
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        for item in items:
            inc_id = item["name"]
            props = item["properties"]
            inc_num = props.get("incidentNumber", 0)
            conn.execute(
                "INSERT OR IGNORE INTO ticket_state (incident_id, incident_number, updated_at) VALUES (?, ?, ?)",
                (inc_id, inc_num, datetime.now(timezone.utc).isoformat()),
            )
            local = dict(conn.execute("SELECT * FROM ticket_state WHERE incident_id = ?", (inc_id,)).fetchone())
            notes = [
                dict(n)
                for n in conn.execute(
                    "SELECT * FROM work_notes WHERE incident_id = ? ORDER BY created_at DESC", (inc_id,)
                ).fetchall()
            ]
            results.append({
                "incident_id": inc_id,
                "ticket_number": f"INC-{inc_num:05d}",
                "title": props.get("title"),
                "description": props.get("description", ""),
                "severity": props.get("severity"),
                "sentinel_status": props.get("status"),
                "created_time": props.get("createdTimeUtc"),
                "tactics": props.get("tactics", []),
                "assigned_to": local["assigned_to"],
                "snow_state": local["snow_state"],
                "ai_analysis": local["ai_analysis"],
                "work_notes": notes,
            })
    return results

@app.post("/api/incidents/{incident_id}/assign")
def assign_incident(incident_id: str, body: AssignRequest):
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT name FROM analysts WHERE id = ?", (body.analyst_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Analyst not found")
        analyst_name = row[0]
        new_state = "New" if body.analyst_id == "bin" else "In Progress"
        conn.execute(
            "UPDATE ticket_state SET assigned_to = ?, snow_state = ?, updated_at = ? WHERE incident_id = ?",
            (analyst_name, new_state, datetime.now(timezone.utc).isoformat(), incident_id),
        )
    return {"incident_id": incident_id, "assigned_to": analyst_name, "snow_state": new_state}

@app.post("/api/incidents/{incident_id}/notes")
async def add_bidirectional_work_note(incident_id: str, body: WorkNoteRequest):
    arm_token = await get_azure_token("https://management.azure.com/.default")
    headers = {"Authorization": f"Bearer {arm_token}", "Content-Type": "application/json"}
    comment_id = str(uuid.uuid4())

    async with httpx.AsyncClient(timeout=20) as client:
        # 1. Push comment into Microsoft Sentinel Incident
        comment_url = f"{SENTINEL_BASE}/incidents/{incident_id}/comments/{comment_id}?api-version={SENTINEL_API_VER}"
        c_resp = await client.put(
            comment_url,
            headers=headers,
            json={"properties": {"message": f"[MKRYPT SOC Portal - {body.author}]: {body.note}"}},
        )
        if c_resp.status_code not in (200, 201):
            raise HTTPException(status_code=c_resp.status_code, detail=f"Sentinel comment sync failed: {c_resp.text}")

        # 2. Optionally update Sentinel Incident Status (Active / Closed / New)
        if body.new_status in {"Active", "Closed", "New"}:
            inc_url = f"{SENTINEL_BASE}/incidents/{incident_id}?api-version={SENTINEL_API_VER}"
            get_inc = await client.get(inc_url, headers=headers)
            if get_inc.status_code == 200:
                inc_payload = get_inc.json()
                inc_payload["properties"]["status"] = body.new_status
                if body.new_status == "Closed":
                    inc_payload["properties"]["classification"] = "TruePositive"
                    inc_payload["properties"]["classificationComment"] = body.note
                await client.put(inc_url, headers=headers, json=inc_payload)

    now_iso = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO work_notes (id, incident_id, author, note, synced_to_sentinel, created_at) VALUES (?, ?, ?, ?, 1, ?)",
            (comment_id, incident_id, body.author, body.note, now_iso),
        )
        if body.new_status:
            snow_map = {"New": "New", "Active": "In Progress", "Closed": "Resolved"}
            conn.execute(
                "UPDATE ticket_state SET snow_state = ?, updated_at = ? WHERE incident_id = ?",
                (snow_map.get(body.new_status, "In Progress"), now_iso, incident_id),
            )

    return {"status": "Synced to Sentinel", "comment_id": comment_id}

# --- 6. One-Click Gemini AI Triage (3-Query KQL Context + Gemini 2.5 Flash) ---
@app.post("/api/incidents/{incident_id}/ai-triage")
async def gemini_ai_triage(incident_id: str):
    if not GEMINI_KEY:
        raise HTTPException(status_code=500, detail="GEMINI_API_KEY is missing in .env")

    arm_token = await get_azure_token("https://management.azure.com/.default")
    inc_url = f"{SENTINEL_BASE}/incidents/{incident_id}?api-version={SENTINEL_API_VER}"
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(inc_url, headers={"Authorization": f"Bearer {arm_token}"})
        if resp.status_code != 200:
            raise HTTPException(
                status_code=resp.status_code,
                detail=f"Incident lookup failed ({resp.status_code}): {resp.text}",
            )
        inc = resp.json()["properties"]

    title = inc.get("title", "")
    safe_title = title.replace("'", "''")

    trend_kql = f"""
    SecurityAlert
    | where TimeGenerated > ago(7d) and AlertName has '{safe_title}'
    | make-series AlertCount=count() default=0 on TimeGenerated from ago(7d) to now() step 1d
    | extend (anomalies, score, baseline) = series_decompose_anomalies(AlertCount, 1.5, -1, 'linefit')
    """
    host_pattern_kql = """
    union isfuzzy=true
      (SecurityEvent | where TimeGenerated > ago(1h) | project TimeGenerated, Computer, EventID=tostring(EventID), Detail=Activity),
      (Syslog | where TimeGenerated > ago(1h) | project TimeGenerated, Computer, EventID=Facility, Detail=SyslogMessage)
    | top 20 by TimeGenerated desc
    """
    related_alerts_kql = """
    SecurityAlert
    | where TimeGenerated > ago(24h)
    | summarize Count=count(), Tactics=make_set(Tactics) by AlertName, AlertSeverity, CompromisedEntity
    | top 15 by Count desc
    """

    trend_data, host_events, related_alerts = await asyncio.gather(
        run_kql(trend_kql, "P7D"),
        run_kql(host_pattern_kql, "PT1H"),
        run_kql(related_alerts_kql, "P1D"),
    )

    prompt = f"""
    You are a Senior SOC Incident Responder analyzing a live Microsoft Sentinel incident from a hybrid lab (Windows Server 2022 'Win-Victim-01', Ubuntu 'VM-1', and Windows Host 'MOHAN_KRISHNA').

    INCIDENT METADATA:
    - Title: {title}
    - Severity: {inc.get('severity')}
    - Description: {inc.get('description')}
    - MITRE Tactics: {inc.get('tactics')}

    1. 7-DAY HISTORICAL TREND & ANOMALY DECOMPOSITION (KQL series_decompose_anomalies):
    {trend_data}

    2. RECENT HOST TELEMETRY PATTERN (Last 1 Hour SecurityEvent & Syslog):
    {host_events}

    3. RELATED ALERTS & ENTITIES (Last 24 Hours):
    {related_alerts}

    Provide a concise, actionable SOC triage report covering:
    1. **Verdict & Confidence** (True Positive / Benign Positive / False Positive)
    2. **Trend & Anomaly Verification** (Is this a baseline spike or recurring noise based on the 7-day series?)
    3. **Pattern & Related Activity Correlation** (Connect the host logs and related alerts)
    4. **Containment & Remediation Steps** (Specific commands/actions for Windows/Linux)
    """

    analysis_text = None
    last_error = ""
    for model_name in ("gemini-3.5-flash", "gemini-3.5-flash-lite", "gemini-2.5-pro"):        
        for attempt in range(2):
            try:
                ai_resp = await asyncio.to_thread(
                    gemini_client.models.generate_content,
                    model=model_name,
                    contents=prompt,
                )
                if ai_resp and ai_resp.text:
                    analysis_text = ai_resp.text
                    break
            except Exception as exc:
                last_error = f"{model_name} (attempt {attempt + 1}): {exc}"
                await asyncio.sleep(1.5)
        if analysis_text:
            break

    if not analysis_text:
        raise HTTPException(
            status_code=502,
            detail=f"Gemini triage error — {last_error}",
        )

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE ticket_state SET ai_analysis = ?, updated_at = ? WHERE incident_id = ?",
            (analysis_text, datetime.now(timezone.utc).isoformat(), incident_id),
        )

    return {"incident_id": incident_id, "ai_analysis": analysis_text}
