#imports
import os, re, json, requests, time
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from requests.exceptions import ReadTimeout, ConnectionError

#Load variables from .env file
load_dotenv()
#disable SSL warnings as the project uses local certificates
requests.packages.urllib3.disable_warnings()

# -----------------------------
# Environment / configuration
# -----------------------------

# Ollama configuration
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b") 

# Wazuh API configuration
WAZUH_API = os.getenv("WAZUH_API", "https://127.0.0.1:55000")
WAZUH_USER = os.getenv("WAZUH_USER")
WAZUH_PASS = os.getenv("WAZUH_PASS")

# Wazuh/OpenSearch indexer configuration
INDEXER_URL = os.getenv("INDEXER_URL", "https://127.0.0.1:9200")
INDEXER_USER = os.getenv("INDEXER_USER")
INDEXER_PASS = os.getenv("INDEXER_PASS")

SIM_RUNNER_URL = os.getenv("SIM_RUNNER_URL", "http://192.168.21.129:8766/run")
SIM_RUNNER_KEY = os.getenv("SIM_RUNNER_KEY", "")

# Limit searches/charts to these Windows agents
WINDOWS_AGENTS = ["DESKTOP-EU8RGOH"]
# -----------------------------
# Authentication / API helpers
# -----------------------------

def get_token():
    """
    Authenticate with the Wazuh API and return a JWT token.
    """
    url = f"{WAZUH_API}/security/user/authenticate"
    r = requests.post(url, auth=(WAZUH_USER, WAZUH_PASS), verify=False)
    r.raise_for_status()
    return r.json()["data"]["token"]
    
def api_get(path, token, params=None):
    """
    Generic GET wrapper for the Wazuh API.
    If the token has expired (401), it refreshes once and retries.
    """
    url = f"{WAZUH_API}{path}"
    headers = {"Authorization": f"Bearer {token}"}

    r = requests.get(url, headers=headers, params=params, verify=False)

    # Refresh token if it has expired
    if r.status_code == 401:
        new_token = get_token()
        st.session_state.token = new_token
        headers = {"Authorization": f"Bearer {new_token}"}
        r = requests.get(url, headers=headers, params=params, verify=False)

    r.raise_for_status()
    return r
    
def reply(role="assistant", content="", table=None, rerun=True):
    """
    Add a message to Streamlit session state and optionally rerun the app.
    """
    msg = {"role": role, "content": content}
    if table is not None:
        msg["table"] = table
    st.session_state.messages.append(msg)
    if rerun:
        st.rerun()
        st.stop()

# -----------------------------
# Ollama / LLM helpers
# -----------------------------

@st.cache_resource
def warm_ollama():
    """
    Sends a small test prompt to Ollama to warm it up when the app starts.
    Cached so it only happens once.
    """
    try:
        ollama_chat([{"role":"user","content":"Say OK"}], timeout_s=60)
        return True
    except:
        return False

warm_ollama()

def ollama_chat(messages, model=OLLAMA_MODEL, temperature=0.2, force_json=False, timeout_s=180):
    """
    Send a chat request to Ollama.
    Supports optional JSON-only mode for structured LLM output.
    """
    url = f"{OLLAMA_URL}/api/chat"
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": temperature},
    }
    if force_json:
        payload["format"] = "json"

    r = requests.post(url, json=payload, timeout=timeout_s)
    r.raise_for_status()
    return (r.json().get("message") or {}).get("content", "")
    
def build_style_prompt(style: str) -> str:
    """
    Builds a system prompt depending on which response style
    the user selected in the UI.
    """
    if style == "SOC summary":
        return (
            "Write a short SOC analyst summary. "
            "Be concise, practical, and focused on what happened."
        )
    if style == "Detailed analysis":
        return (
            "Write a detailed analyst explanation. "
            "Explain the likely behaviour, why it matters, and what the alerts suggest."
        )
    if style == "Executive summary":
        return (
            "Write a high-level executive summary. "
            "Avoid deep technical detail. Focus on risk, impact, and overall significance."
        )
    if style == "Mitigation advice":
        return (
            "Write a response focused on mitigation and next steps. "
            "Explain what should be investigated, contained, or improved."
        )
    return "Write a clear SOC summary."

def explain_alerts_with_style(user_question: str, alerts_rows: list, response_style: str, time_window: str):
    """
    Ask Ollama to explain a small sample of retrieved alerts
    using the chosen response style.
    """
    sample = alerts_rows[:8]

    system_prompt = (
        "You are a SOC analyst assistant helping interpret Wazuh alerts. "
        "Use only the provided alert data. "
        "Do not invent alerts or evidence that are not present.\n\n"
        f"{build_style_prompt(response_style)}"
    )

    user_payload = {
        "question": user_question,
        "time_window": time_window,
        "total_alerts": len(alerts_rows),
        "alerts": sample
    }

    try:
        return ollama_chat(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_payload)}
            ],
            temperature=0.4,
            force_json=False,
            timeout_s=180
        )
    except Exception as e:
        return (
            f"(LLM unavailable) Retrieved {len(alerts_rows)} alerts in {time_window}. "
            f"Top investigation areas: suspicious process execution, file drops, and related child processes. "
            f"Error: {e}"
        )    

# -----------------------------
# Small utility functions
# -----------------------------

def deep_get(obj, path, default=None):
    """
    Safely retrieve nested dictionary values.
    Example: deep_get(src, ['agent', 'name'])
    """
    cur = obj
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return cur

def first_non_empty(*values):
    """
    Return the first value that is not empty / None.
    Useful when alert fields can exist in multiple places.
    """
    for v in values:
        if v is None:
            continue
        if isinstance(v, str) and not v.strip():
            continue
        if isinstance(v, (list, dict)) and not v:
            continue
        return v
    return None
    
def llm_interpret(user_text):
    """
    Ask Ollama to classify the user's message into a structured JSON format.
    """
    system = """
You are a SOC assistant.
Return JSON only. No markdown. No code fences.

Keys:
intent, technique, test, agent, time_window, explanation

If unknown, set intent="unknown".
"""
    reply = ollama_chat([
        {"role":"system","content":system},
        {"role":"user","content":user_text}
    ], temperature=0.1, force_json=True)

    return extract_json_obj(reply)

def extract_json_obj(text: str):
    """
    Extract the first JSON object from an LLM response.
    Handles code fences or extra surrounding text.
    """
    if not text:
        raise ValueError("Empty LLM response")

    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)

    try:
        return json.loads(text)
    except Exception:
        pass

    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        raise ValueError(f"LLM did not return JSON. Got: {text[:200]}")
    return json.loads(m.group(0))

def window_to_range(window: str):
    """
    Convert the UI time window into an OpenSearch range query.
    """
    if window == "Last 15 minutes":
        return {"gte": "now-15m", "lt": "now"}
    if window == "Last hour":
        return {"gte": "now-1h", "lt": "now"}
    if window == "Today":
        return {"gte": "now/d", "lt": "now"}
    return {"gte": "now-7d", "lt": "now"}
    
def looks_like_tool_request(text: str) -> bool:
    """
    Decide whether the user is asking for a tool-based action
    (search alerts, run simulation, render chart, etc.)
    rather than just general conversation.
    """
    t = text.lower().strip()

    tool_phrases = [
        "agent", "agents",
        "alert", "alerts",
        "log", "logs",
        "event", "events",
        "show mitre", "mitre", "technique", "techniques", "att&ck",
        "sysmon", "powershell", "logon", "malware",
        "run atomic", "setup atomic",
        "run simulation", "list simulations",
        "list investigations", "run investigation", "save investigation", "delete investigation",
        "pie chart", "bar chart", "render chart", "render a chart",
        "source ip", "source ips", "destination ip", "destination ips",
        "high alerts", "critical alerts", "failed login", "failed logins",
        "what happened"
    ]

    time_phrases = [
        "last ", "past ", "today", "yesterday", "this week", "last week",
        "last hour", "last day", "last 5 days", "last 7 days"
    ]

    return any(p in t for p in tool_phrases) or any(p in t for p in time_phrases)

def llm_route(user_text: str, time_window: str, agent_filter: str, min_level: int, keyword: str):
    """
    Use Ollama to decide which internal tool/action should handle the user's request.
    """
    system = f"""
You are routing user requests for a Wazuh SOC assistant.

Return JSON only with:
tool: one of ["help","list_agents","show_mitre","search_alerts","run_atomic","run_simulation","render_chart","general_chat"]
args: object
explanation: string

Rules:
- NEVER invent alerts or results.
- Prefer "search_alerts" when the user asks about alerts, sysmon, logins, powershell, malware.
- Prefer "show_mitre" when user asks about MITRE techniques/attacks summary.
- Prefer "run_atomic" only if user explicitly asks to run an atomic test or mentions "atomic".
- Prefer "run_simulation" only if user explicitly asks to run a simulation or mentions "simulation".
- If unclear, tool="help".

Context (UI):
- time_window is "{time_window}"
- agent_filter is "{agent_filter}"
- min_level is {min_level}
- keyword is "{keyword}"

For search_alerts args, include ONLY:
- limit (int 1-100)
- agent (optional string)
- categories (optional list of strings from ["sysmon","powershell","logon","malware"])
- keywords (optional list of strings)
- severity_min (optional int 0-15)
- time_minutes (optional int)
- days_ago (optional int)
DO NOT include "query".

For run_atomic args, include:
- technique (e.g. "T1059.001")
- test (int)
- agent

For render_chart args, include:
- chart_type (one of ["pie","bar"])
- field (one of ["srcip","dstip","agent","level","mitre_id"])
- limit (optional int 1-100)
- time_minutes (optional int)

For run_simulation args, include:
- simulation_id
- agent
"""

    reply = ollama_chat([
        {"role": "system", "content": system},
        {"role": "user", "content": user_text}
    ], temperature=0.1, force_json=True)

    plan = extract_json_obj(reply)

    tool = plan.get("tool", "help")
    if tool not in ["help","list_agents","show_mitre","search_alerts","run_simulation","run_atomic","render_chart","general_chat"]:
        tool = "help"

    args = plan.get("args") or {}

    # Clamp result limit to a safe range
    if "limit" in args:
        try:
            args["limit"] = max(1, min(int(args["limit"]), 100))
        except Exception:
            args["limit"] = 20

    return {"tool": tool, "args": args, "explanation": plan.get("explanation", "")}
    
def get_llm_history():
    """
    Retrieve or initialise the assistant conversation history.
    Used so follow-up questions still make sense.
    """
    if "llm_history" not in st.session_state:
        st.session_state.llm_history = [
            {"role":"system","content":(
                "You are a SOC assistant helping a student analyse Wazuh alerts. "
                "Be concise, practical, and never invent logs. "
                "When you reference alerts, only use what the tool returned in the provided context."
            )}
        ]
    return st.session_state.llm_history
    
def collect_recent_mitre_ids(rows: list) -> list[str]:
    """
    Collect unique MITRE IDs from alert rows so follow-up questions
    can refer back to the latest MITRE techniques found.
    """
    ids = []
    for r in rows or []:
        mid = r.get("mitre_id")
        if not mid:
            continue
        for part in str(mid).split(","):
            part = part.strip().upper()
            if part and part not in ids:
                ids.append(part)
    return ids

def llm_add(role, content):
    """
    Add a message to LLM history and keep only the most recent items.
    """
    hist = get_llm_history()
    hist.append({"role": role, "content": content})
    MAX_MSGS = 16
    st.session_state.llm_history = hist[:1] + hist[-MAX_MSGS:]
    
def explain_with_llm(user_question: str, time_window: str, alerts_rows: list):
    """
    Use recent alert results plus conversation history
    to explain alerts in a more natural conversational way.
    """
    sample = alerts_rows[:8]

    context = {
        "question": user_question,
        "time_window": time_window,
        "count": len(alerts_rows),
        "examples": sample
    }

    llm_add("user", user_question)

    try:
        answer = ollama_chat(
            get_llm_history() + [
                {"role":"system","content":(
                    "Use the provided JSON context to answer. "
                    "If the user asks 'why' or 'what does it mean', explain the alerts. "
                    "If the user asks a follow-up, use chat history. "
                    "Do not invent extra alerts beyond what is in context."
                )},
                {"role":"user","content": json.dumps(context)}
            ],
            temperature=0.4,
            force_json=False,
            timeout_s=180
        )
    except Exception as e:
        answer = f"(LLM offline) I pulled {len(alerts_rows)} alerts for {time_window}. Ask me to filter by Sysmon/PowerShell/logon or severity. Error: {e}"

    llm_add("assistant", answer)
    return answer
    
def args_to_time_range(args: dict, fallback_window: str, user_text: str):
    """
    Resolve time range using:
    1. Explicit 'X days ago' in user text
    2. time_minutes from LLM arguments
    3. fallback UI dropdown
    """
    explicit = parse_days_ago_range(user_text)
    if explicit:
        return explicit

    tm = args.get("time_minutes")
    if tm:
        try:
            n = max(1, min(int(tm), 10080))
            return {"gte": f"now-{n}m", "lt": "now"}
        except Exception:
            pass

    return window_to_range(fallback_window)

def build_lucene_query(categories=None, keywords=None, severity_min=None, agent=None):
    """
    Build a Lucene query string for OpenSearch based on categories,
    keywords, severity and agent filter.
    """
    parts = []

    if categories:
        cats = []
        for c in categories:
            c = c.lower()
            if c == "sysmon":
                cats.append('(winlog.channel:"Microsoft-Windows-Sysmon/Operational" OR rule.groups:sysmon OR sysmon)')
            elif c == "powershell":
                cats.append('(powershell OR winlog.event_data.ScriptBlockText:* OR rule.description:*PowerShell*)')
            elif c == "logon":
                cats.append('(logon OR winlog.event_id:(4624 OR 4625) OR rule.groups:authentication)')
        if cats:
            parts.append("(" + " OR ".join(cats) + ")")

    if severity_min is not None:
        parts.append(f"rule.level:[{int(severity_min)} TO *]")

    if agent:
        safe_agent = agent.replace('"', '\\"')
        parts.append(f'agent.name:"{safe_agent}"')

    if keywords:
        for kw in keywords:
            kw = str(kw).strip()
            if not kw:
                continue
            safe_kw = kw.replace('"', '\\"')
            parts.append(f'rule.description:"{safe_kw}"')

    return " AND ".join(parts) if parts else "*"

def pick_default_agent(token):
    """
    Choose a default active agent, falling back to the first agent if needed.
    """
    agents = list_agents(token)
    active = [a for a in agents if a.get("status") == "active"]
    if active:
        return active[0]["name"]
    return agents[0]["name"] if agents else None

# -----------------------------
# Simulation handling
# -----------------------------

SIM_FILE = "simulations.json"

def load_simulations(path=SIM_FILE):
    """
    Load simulation definitions from JSON file.
    Returns a dictionary keyed by simulation id.
    """
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        sims = json.load(f)
    return {s["id"]: s for s in sims}

def parse_sim_command(text: str):
    """
    Parse supported simulation commands:
    - list simulations
    - run simulation <id> on <agentname>
    """
    t = text.strip()

    if re.fullmatch(r"(?i)\s*list\s+simulations\s*", t):
        return ("list", None, None)

    m = re.match(r"(?i)\s*run\s+simulation\s+([a-z0-9_.-]+)\s+on\s+([A-Za-z0-9_.-]+)\s*$", t)
    if m:
        return ("run", m.group(1), m.group(2))

    return (None, None, None)

def trigger_simulation(sim_id: str):
    """
    Send a simulation request to the external simulation runner service.
    """
    headers = {"Content-Type": "application/json"}
    if SIM_RUNNER_KEY:
        headers["X-API-Key"] = SIM_RUNNER_KEY

    payload = {"simulation_id": sim_id}

    r = requests.post(
        SIM_RUNNER_URL,
        headers=headers,
        data=json.dumps(payload),
        timeout=10
    )
    r.raise_for_status()
    return r.json() if r.text else {}

def call_runner(payload: dict):
    """
    Generic helper to call the simulation/atomic runner with a JSON payload.
    """
    headers = {"Content-Type": "application/json"}
    if SIM_RUNNER_KEY:
        headers["X-API-Key"] = SIM_RUNNER_KEY

    r = requests.post(
        SIM_RUNNER_URL,
        headers=headers,
        data=json.dumps(payload),
        timeout=10
    )
    r.raise_for_status()
    return r.json() if r.text else {}

def poll_for_marker(agent_name: str, marker: str, started_at_iso: str, timeout_s=90):
    """
    Poll OpenSearch until an alert containing the marker string appears
    or until timeout.
    """
    time_range = {"gte": started_at_iso, "lt": "now"}
    deadline = time.time() + timeout_s

    while time.time() < deadline:
        q = f'(agent.name:*{agent_name}*) AND full_log:"{marker}"'
        alerts = search_alerts(limit=50, query=q, time_range=time_range)
        if alerts:
            return alerts
        time.sleep(2)

    return []

# -----------------------------
# Atomic Red Team handling
# -----------------------------

def parse_atomic_command(text: str):
    """
    Parse supported Atomic commands:
    - setup atomic
    - run atomic T1059.001 1 on DESKTOP-XXXX
    """
    t = text.strip()

    if re.fullmatch(r"(?i)\s*setup\s+atomic\s*$", t):
        return ("setup", None, None, None)

    m = re.match(r"(?i)\s*run\s+atomic\s+(T\d{4}(?:\.\d{3})?)\s+(\d+)\s+on\s+([A-Za-z0-9_.-]+)\s*$", t)
    if m:
        return ("run", m.group(1), int(m.group(2)), m.group(3))

    return (None, None, None, None)
    
def parse_chart_command(text: str):
    """
    Parse natural language chart requests, such as:
    - render a pie chart of source ips
    - show a bar chart of alerts by level
    """
    t = text.lower().strip()

    chart_type = None
    if "pie chart" in t:
        chart_type = "pie"
    elif "bar chart" in t or "chart" in t:
        chart_type = "bar"

    if not chart_type:
        return None, None

    field = None
    if any(k in t for k in ["source ip", "source ips", "src ip", "src ips"]):
        field = "srcip"
    elif any(k in t for k in ["destination ip", "destination ips", "dest ip", "dst ip", "dst ips"]):
        field = "dstip"
    elif "agent" in t or "agents" in t:
        field = "agent"
    elif "level" in t or "severity" in t:
        field = "level"
    elif "mitre" in t:
        field = "mitre_id"

    if not field:
        return None, None

    return chart_type, field

# -----------------------------
# Wazuh / alert retrieval
# -----------------------------

def list_agents(token):
    """
    Retrieve all agents from the Wazuh API.
    """
    r = api_get("/agents", token, params={"pretty": "true"})
    items = r.json()["data"]["affected_items"]
    return [
        {"id": a.get("id"), "name": a.get("name"), "status": a.get("status"), "ip": a.get("ip")}
        for a in items
    ]

def search_alerts(limit=10, query="*", time_range=None):
    """
    Query Wazuh alerts from OpenSearch.
    Returns normalised alert rows for display in the Streamlit app.
    """
    url = f"{INDEXER_URL}/wazuh-alerts-*/_search"

    must = [{
        "query_string": {
            "query": query,
            "default_operator": "AND",
            "lenient": True
        }
    }]

    if time_range:
        must.append({"range": {"@timestamp": time_range}})

    body = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}}
    }

    r = requests.post(
        url,
        auth=(INDEXER_USER, INDEXER_PASS),
        headers={"Content-Type": "application/json"},
        data=json.dumps(body),
        verify=False
    )
    if r.status_code >= 400:
        raise RuntimeError(f"OpenSearch {r.status_code}: {r.text}\nQuery was: {json.dumps(body, indent=2)}")
        
    r.raise_for_status()

    hits = r.json().get("hits", {}).get("hits", [])
    out = []
    for h in hits:
        src = h.get("_source", {}) or {}
        rule = src.get("rule") or {}
        mitre = rule.get("mitre") or {}
        data = src.get("data", {}) or {}

        # Try multiple possible locations for source/destination IPs
        srcip = first_non_empty(
            deep_get(src, ["data", "srcip"]),
            deep_get(src, ["data", "src_ip"]),
            deep_get(src, ["srcip"]),
            deep_get(src, ["src_ip"]),
            deep_get(src, ["source", "ip"]),
            deep_get(src, ["winlog", "event_data", "IpAddress"]),
            deep_get(src, ["winlog", "event_data", "SourceNetworkAddress"]),
            deep_get(src, ["data", "win", "eventdata", "ipAddress"]),
        )

        dstip = first_non_empty(
            deep_get(src, ["data", "dstip"]),
            deep_get(src, ["data", "dst_ip"]),
            deep_get(src, ["dstip"]),
            deep_get(src, ["dst_ip"]),
            deep_get(src, ["destination", "ip"]),
            deep_get(src, ["winlog", "event_data", "DestinationIp"]),
        )

        out.append({
            "timestamp": src.get("@timestamp") or src.get("timestamp"),
            "agent": first_non_empty(
                deep_get(src, ["agent", "name"]),
                src.get("agent")
            ),
            "level": rule.get("level"),
            "description": rule.get("description"),
            "srcip": srcip,
            "dstip": dstip,
            "mitre_id": ", ".join(mitre.get("id", [])) if isinstance(mitre.get("id"), list) else mitre.get("id"),
            "mitre_tactic": ", ".join(mitre.get("tactic", [])) if isinstance(mitre.get("tactic"), list) else mitre.get("tactic"),
            "mitre_technique": ", ".join(mitre.get("technique", [])) if isinstance(mitre.get("technique"), list) else mitre.get("technique"),
        })
    return out

def search_detections_since(agent_name: str, started_at_iso: str, limit: int = 50):
    """
    Retrieve detections for one agent since a given time,
    excluding simrunner metadata alerts.
    """
    q = f'agent.name:"{agent_name}" AND NOT rule.groups:simrunner'
    tr = {"gte": started_at_iso, "lt": "now"}
    return search_alerts(limit=limit, query=q, time_range=tr)

def poll_for_detections(agentname: str, started_at_iso: str, timeout_s: int = 90, interval_s: int = 5):
    """
    Poll repeatedly for detections after running an Atomic test.
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        det = search_detections_since(agentname, started_at_iso, limit=50)
        if det:
            return det
        time.sleep(interval_s)
    return []

# -----------------------------
# Chart helpers
# -----------------------------

def chart_dataframe_from_rows(rows: list, field: str, top_n: int = 10) -> pd.DataFrame:
    """
    Convert alert rows into a grouped dataframe for charting.
    """
    values = []

    for r in rows:
        value = r.get(field)

        # MITRE IDs may be comma separated, so split them out
        if field == "mitre_id" and value:
            values.extend([x.strip() for x in str(value).split(",") if x.strip()])
        elif value is not None and str(value).strip() != "":
            values.append(str(value))

    if not values:
        return pd.DataFrame(columns=[field, "count"])

    counts = Counter(values).most_common(top_n)
    return pd.DataFrame(counts, columns=[field, "count"])

def render_chart(df: pd.DataFrame, chart_type: str, field: str):
    """
    Render either a bar chart or pie chart in Streamlit.
    """
    if df.empty:
        st.info(f"No data available to render a {chart_type} chart for {field}.")
        return

    if chart_type == "bar":
        st.bar_chart(df.set_index(field))
        return

    fig, ax = plt.subplots(figsize=(6, 6))
    ax.pie(df["count"], labels=df[field], autopct="%1.1f%%")
    ax.set_title(f"Top {field}")
    st.pyplot(fig)

# -----------------------------
# Alert formatting / display
# -----------------------------

def format_alerts(alerts):
    """
    Build a short markdown summary and tabular rows
    from a list of alert dictionaries.
    """
    if not alerts:
        return "No alerts matched that query.", []

    levels = {}
    for a in alerts:
        lvl = a.get("level")
        levels[lvl] = levels.get(lvl, 0) + 1

    top = sorted(levels.items(), key=lambda x: (x[0] is None, x[0]), reverse=True)
    level_summary = ", ".join([f"L{lvl}={cnt}" for lvl, cnt in top if lvl is not None])

    highlights = []
    for a in alerts[:5]:
        highlights.append(
            f"- **{a.get('timestamp')}** | **{a.get('agent')}** | **L{a.get('level')}** — {a.get('description')}"
        )

    summary = (
        f"Returned **{len(alerts)}** alerts.\n\n"
        f"**Level breakdown:** {level_summary if level_summary else 'N/A'}\n\n"
        f"**Top highlights:**\n" + "\n".join(highlights)
    )

    return summary, alerts

# -----------------------------
# Saved investigations
# -----------------------------

INVESTIGATIONS_FILE = "investigations.json"

def load_investigations():
    """
    Load saved investigation definitions from disk.
    """
    if not os.path.exists(INVESTIGATIONS_FILE):
        return {}
    try:
        with open(INVESTIGATIONS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}
        
def ensure_defaults(investigations: dict):
    """
    Ensure a default investigation exists.
    """
    key = normalise_name("yesterday suspicious activity")
    if key not in investigations:
        investigations[key] = {
            "query": "rule.level:[10 TO *] OR rule.description:*suspicious*",
            "time": "@timestamp:[now-1d/d TO now/d]",
            "limit": 50,
            "notes": "High severity + suspicious keyword"
        }
    return investigations

def save_investigations(data: dict):
    """
    Save investigations back to disk.
    """
    with open(INVESTIGATIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def normalise_name(name: str) -> str:
    """
    Convert investigation names to a standard lowercase format.
    """
    return re.sub(r"\s+", " ", name.strip().lower())

def parse_investigation_command(text: str):
    """
    Parse commands for investigation management.
    """
    t = text.strip()

    m = re.search(r"^\s*(list|show)\s+investigations\s*$", t, re.IGNORECASE)
    if m:
        return ("list", None)

    m = re.search(r"^\s*(run|open|show)\s+investigation\s+(.+?)\s*$", t, re.IGNORECASE)
    if m:
        return ("run", m.group(2))

    m = re.search(r"^\s*delete\s+investigation\s+(.+?)\s*$", t, re.IGNORECASE)
    if m:
        return ("delete", m.group(1))

    m = re.search(r"^\s*save\s+investigation\s+(.+?)\s*$", t, re.IGNORECASE)
    if m:
        return ("save", m.group(1))

    return (None, None)

# -----------------------------
# MITRE helpers
# -----------------------------

def mitre_fallback(description: str):
    """
    Very small rule-based fallback MITRE mapping when the alert
    does not already contain MITRE metadata.
    """
    if not description:
        return None, None, None

    d = description.lower()

    mapping = [
        (["powershell"], "T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"),
        (["command prompt", "cmd.exe"], "T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "Execution"),
        (["account discovery", "net.exe"], "T1087", "Account Discovery", "Discovery"),
        (["name resolution", "dns"], "T1046", "Network Service Scanning", "Discovery"),
        (["executable dropped", "dropped in folder"], "T1105", "Ingress Tool Transfer", "Command and Control"),
        (["logon success", "logon"], "T1078", "Valid Accounts", "Initial Access"),
    ]

    for keys, tid, tname, tactic in mapping:
        if any(k in d for k in keys):
            return tid, tname, tactic

    return None, None, None
    
def apply_mitre_fallback(rows: list):
    """
    Fill in MITRE fields on alert rows if they are missing.
    """
    for r in rows:
        if not r.get("mitre_id"):
            tid, tname, tactic = mitre_fallback(r.get("description", ""))
            r["mitre_id"] = tid
            r["mitre_technique"] = tname
            r["mitre_tactic"] = tactic
    return rows

def top_mitre_summary(rows, top_n=5):
    """
    Summarise the most common MITRE techniques from a set of alert rows.
    """
    counts = {}
    meta = {}

    for r in rows:
        tid = r.get("mitre_id")
        if not tid:
            continue

        ids = [x.strip() for x in str(tid).split(",") if x.strip()]
        for one in ids:
            counts[one] = counts.get(one, 0) + 1
            if one not in meta:
                meta[one] = {
                    "technique": r.get("mitre_technique"),
                    "tactic": r.get("mitre_tactic")
                }

    if not counts:
        return "No MITRE techniques were mapped for these alerts."

    ranked = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top_n]

    lines = []
    for tid, cnt in ranked:
        tech = meta.get(tid, {}).get("technique") or ""
        tac = meta.get(tid, {}).get("tactic") or ""
        extra = []
        if tech:
            extra.append(tech)
        if tac:
            extra.append(tac)

        suffix = f" — {' | '.join(extra)}" if extra else ""
        lines.append(f"- **{tid}** ×{cnt}{suffix}")

    return "**Top MITRE techniques:**\n" + "\n".join(lines)

def get_mitre_attacks(time_range=None, limit=20, agent=None):
    """
    Query OpenSearch aggregations to return top MITRE ATT&CK IDs.
    """
    url = f"{INDEXER_URL}/wazuh-alerts-*/_search"

    must = []
    if time_range:
        must.append({"range": {"@timestamp": time_range}})
    if agent and agent.strip():
        must.append({"term": {"agent.name.keyword": agent.strip()}})

    must.append({"exists": {"field": "rule.mitre.id"}})

    body = {
        "size": 0,
        "query": {"bool": {"must": must}},
        "aggs": {
            "mitre_ids": {
                "terms": {
                    "field": "rule.mitre.id.keyword",
                    "size": limit
                },
                "aggs": {
                    "top_hit": {
                        "top_hits": {
                            "size": 1,
                            "_source": ["rule.mitre", "rule.description"]
                        }
                    }
                }
            }
        }
    }

    r = requests.post(
        url,
        auth=(INDEXER_USER, INDEXER_PASS),
        headers={"Content-Type": "application/json"},
        data=json.dumps(body),
        verify=False
    )
    r.raise_for_status()
    buckets = r.json().get("aggregations", {}).get("mitre_ids", {}).get("buckets", [])

    rows = []
    for b in buckets:
        mitre_id = b.get("key")
        count = b.get("doc_count", 0)
        src = (b.get("top_hit", {})
                .get("hits", {})
                .get("hits", [{}])[0]
                .get("_source", {}))
        mitre = (src.get("rule", {}) or {}).get("mitre", {}) or {}
        rows.append({
            "mitre_id": mitre_id,
            "count": count,
            "tactic": ", ".join(mitre.get("tactic", [])) if isinstance(mitre.get("tactic"), list) else mitre.get("tactic"),
            "technique": ", ".join(mitre.get("technique", [])) if isinstance(mitre.get("technique"), list) else mitre.get("technique"),
        })

    return rows

def parse_mitre_command(text: str):
    """
    Check whether the user asked for a MITRE summary.
    """
    t = text.strip().lower()

    mitre_queries = [
        "show mitre",
        "show mitre attacks",
        "mitre attacks",
        "mitre techniques",
        "mitre summary",
        "top mitre"
    ]

    return any(q in t for q in mitre_queries)

# -----------------------------
# Time and text parsing helpers
# -----------------------------

def parse_days_ago_range(text: str):
    """
    Parse phrases like:
    - yesterday
    - 3 days ago
    Returns a UTC day-range dictionary for OpenSearch.
    """
    t = text.lower()

    if "yesterday" in t:
        days = 1
    else:
        m = re.search(r"\b(\d{1,3})\s+days?\s+ago\b", t)
        if not m:
            return None
        days = int(m.group(1))

    now = datetime.now(timezone.utc)
    today_start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    start = today_start - timedelta(days=days)
    end = today_start - timedelta(days=days - 1)
    return {"gte": start.isoformat(), "lt": end.isoformat()}

def human_time(tc: str | None, fallback_window: str | None = None) -> str:
    """
    Turn a raw time clause into something more readable for the response.
    """
    if not tc:
        return f"in {fallback_window.lower()}" if fallback_window else ""

    m = re.search(r"now-(\d+)([mhd])\s+TO\s+now", tc)
    if m:
        n = int(m.group(1))
        unit = m.group(2)
        unit_word = {"m": "minute", "h": "hour", "d": "day"}[unit]
        if n != 1:
            unit_word += "s"
        return f"in the last {n} {unit_word}"

    if "now/d" in tc:
        return "today"
    if "now/w" in tc:
        return "this week"

    return ""

def topic_from_user(user_text: str) -> str:
    """
    Infer the general topic of the user's question.
    """
    t = user_text.lower()
    if "sysmon" in t:
        return "Sysmon alerts"
    if any(k in t for k in ["failed login", "login failed", "brute force"]):
        return "failed login alerts"
    if any(k in t for k in ["powershell", "pwsh"]):
        return "PowerShell-related alerts"
    if any(k in t for k in ["malware", "trojan", "ransomware"]):
        return "malware-related alerts"
    if any(k in t for k in ["high", "critical", "severe"]):
        return "high-severity alerts"
    return "alerts"

def human_filters(agent_target: str | None, agent_filter: str, min_level: int, keyword: str) -> str:
    """
    Build a human-readable description of the currently active filters.
    """
    bits = []
    if agent_target:
        bits.append(f"on **{agent_target}**")
    if agent_filter.strip():
        bits.append(f"matching agent **{agent_filter.strip()}**")
    if min_level > 0:
        bits.append(f"with severity **≥ {min_level}**")
    if keyword.strip():
        bits.append(f"containing **“{keyword.strip()}”**")
    return ", ".join(bits)

def parse_action(text: str) -> str:
    """
    Detect the user's intended action from their wording.
    """
    t = text.lower()
    if any(k in t for k in ["summarise", "summarize", "summary"]):
        return "summarise"
    if any(k in t for k in ["most common", "top rule", "common rule"]):
        return "top_rule"
    if any(k in t for k in ["spike", "spikes", "trend", "increase"]):
        return "spikes"
    return "show"

def parse_agent_target(text: str) -> str | None:
    """
    Extract an explicit agent target from text if present.
    """
    t = text.strip()

    m = re.search(r"\b(?:on|for)\s+agent\s+([A-Za-z0-9_.-]+)\b", t, re.IGNORECASE)
    if m:
        return m.group(1)

    m = re.search(r"\bon\s+([A-Za-z0-9_.-]+)\b", t, re.IGNORECASE)
    if m:
        return m.group(1)

    m = re.search(r"\bagent\s*:\s*([A-Za-z0-9_.-]+)\b", t, re.IGNORECASE)
    if m:
        return m.group(1)

    return None

def parse_severity(text: str) -> str | None:
    """
    Convert severity words into rule.level query ranges.
    """
    t = text.lower()
    if "critical" in t:
        return "rule.level:[12 TO *]"
    if "high" in t or "severe" in t:
        return "rule.level:[10 TO *]"
    if "medium" in t:
        return "rule.level:[7 TO 9]"
    if "low" in t:
        return "rule.level:[0 TO 6]"
    return None

def parse_time_range(text: str) -> str | None:
    """
    Parse natural language time expressions into Lucene time clauses.
    """
    t = text.lower().strip()

    m = re.search(r"(last|past)\s+(\d{1,3})\s*(minute|minutes|min|mins)\b", t)
    if m:
        n = int(m.group(2))
        return f"@timestamp:[now-{n}m TO now]"

    m = re.search(r"(last|past)\s+(\d{1,3})\s*(hour|hours|hr|hrs)\b", t)
    if m:
        n = int(m.group(2))
        return f"@timestamp:[now-{n}h TO now]"

    m = re.search(r"(last|past)\s+(\d{1,3})\s*(day|days)\b", t)
    if m:
        n = int(m.group(2))
        return f"@timestamp:[now-{n}d TO now]"

    if "today" in t:
        return "@timestamp:[now/d TO now]"

    if "this week" in t:
        return "@timestamp:[now/w TO now]"

    if "since yesterday" in t:
        return "@timestamp:[now-1d/d TO now]"
        
    if "yesterday" in t and "since yesterday" not in t:
        return "@timestamp:[now-1d/d TO now/d]"

    return None

def parse_limit(text, default=20):
    """
    Extract a result limit from the text, but avoid mistaking
    time-range numbers for limits.
    """
    t = text.lower()
    if re.search(r"(last|past)\s+\d{1,3}\s*(minute|minutes|min|mins|hour|hours|hr|hrs|day|days)\b", t):
        return default

    m = re.search(r"\b(\d{1,3})\b", text)
    return max(1, min(int(m.group(1)), 100)) if m else default

def time_clause(window: str) -> str:
    """
    Convert dropdown time selection to Lucene time clause.
    """
    if window == "Last 15 minutes":
        return "@timestamp:[now-15m TO now]"
    if window == "Last hour":
        return "@timestamp:[now-1h TO now]"
    if window == "Today":
        return "@timestamp:[now/d TO now]"
    if window == "Last 7 days":
        return "@timestamp:[now-7d TO now]"
    return ""

# -----------------------------
# Streamlit UI setup
# -----------------------------

st.set_page_config(layout="wide")
st.title("Wazuh Assistant")

# Two-column layout
left, right = st.columns([3, 1])

with left:
    st.subheader("Wazuh Dashboard")

    # External link to Wazuh dashboard
    wazuh_url = os.getenv("WAZUH_DASHBOARD_URL", "https://192.168.21.128:443/app/mitre-attack")
    st.link_button("Open Wazuh in a new tab", wazuh_url)

    st.subheader("Chat")

    # Chat box for user queries
    user = st.chat_input("Ask Wazuh (e.g., 'sysmon alerts last 20 minutes', 'high alerts today', 'agents')")
    
    # Dropdown to select time window
    time_window = st.selectbox(
        "Time window",
        ["Last 15 minutes", "Last hour", "Today", "Last 7 days"],
        index=3
    )
    
    # Dropdown to select how explanations should be written
    response_style = st.selectbox(
        "Response style",
        ["SOC summary", "Detailed analysis", "Executive summary", "Mitigation advice"],
        index=0
    )
  
    # Initialise token once
    if "token" not in st.session_state or not st.session_state.token:
        st.session_state.token = get_token()

    # Initialise chat message history
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Quick buttons for common requests
    st.markdown("### Quick actions")
    c1, c2, c3 = st.columns(3)
    if c1.button("Agents"):
        st.session_state.quick_cmd = "agents"
    if c2.button("Sysmon alerts (20)"):
        st.session_state.quick_cmd = "sysmon alerts 20"
    if c3.button("High alerts (20)"):
        st.session_state.quick_cmd = "high alerts 20"

    # Manual filter controls
    st.markdown("### Alert panel")
    agent_filter = st.text_input("Agent name contains", value="")
    min_level = st.slider("Minimum rule level", 0, 15, 0)
    keyword = st.text_input("Keyword contains (description)", value="")
    run_ui = st.empty()

    # Display message history, newest first
    for m in reversed(st.session_state.messages):
        with st.chat_message(m["role"]):
            st.write(m["content"])

            # Render chart if attached to assistant message
            if m["role"] == "assistant" and m.get("chart"):
                chart_info = m["chart"]
                chart_df = pd.DataFrame(chart_info["data"])
                render_chart(
                    chart_df,
                    chart_type=chart_info["chart_type"],
                    field=chart_info["field"]
                )

            # Render table if attached to assistant message
            if m["role"] == "assistant" and m.get("table"):
                st.dataframe(m["table"], use_container_width=True)

    # Use quick command as chat input if button was pressed
    if st.session_state.get("quick_cmd"):
        user = st.session_state.quick_cmd
        st.session_state.quick_cmd = None

    # -----------------------------
    # Main user input handling
    # -----------------------------
    if user:
    
        # Save the user's message to chat history
        st.session_state.messages.append({"role": "user", "content": user})
        
        # Context-aware MITRE follow-up handling
        u = user.lower().strip()

        if any(p in u for p in ["tell me more about the mitre", "explain the mitre", "what is the mitre alert"]):
            last_ids = st.session_state.get("last_mitre_ids", [])
            if last_ids:
                answer = explain_mitre_id(last_ids[0])
            else:
                answer = "I couldn't find a recent MITRE technique in the last retrieved alerts."

            st.session_state.messages.append({
                "role": "assistant",
                "content": answer
            })
            st.rerun()
            st.stop()

        # Handle follow-up explanation questions referring to previous alerts
        u = user.lower().strip()

        FOLLOWUP_WORDS = [
            "why", "explain", "dangerous", "malicious",
            "investigate", "next", "summarise", "summary",
            "most common", "what does", "should i"
        ]

        REFERENCES_ALERTS = ["this", "these", "the alerts", "those", "that activity"]

        if (
            any(w in u for w in FOLLOWUP_WORDS)
            and any(r in u for r in REFERENCES_ALERTS)
            and st.session_state.get("last_rows")
        ):

            rows = st.session_state.get("last_rows", [])
            sample = rows[:6]

            prompt = [
                {
                    "role": "system",
                    "content": (
                        "You are a SOC analyst assistant helping interpret Wazuh alerts. "
                        "Use the provided alerts as evidence. "
                        "Do not invent alerts that are not in the data. "
                        "Explain clearly and give practical investigation advice.\n\n"
                        f"{build_style_prompt(response_style)}"
                    )
                },
                {
                    "role": "user",
                    "content": json.dumps({
                        "question": user,
                        "alerts": sample,
                        "total_alerts": len(rows)
                    })
                }
            ]

            try:
                answer = ollama_chat(prompt, temperature=0.4)
            except Exception:
                answer = (
                    f"(LLM unavailable) I found {len(rows)} alerts. "
                    "Investigate PowerShell execution, dropped executables, and suspicious processes."
                )

            st.session_state.messages.append({
                "role": "assistant",
                "content": answer
            })

            st.rerun()
            st.stop()
            
        # General explanation questions about cybersecurity concepts
        u = user.lower().strip()

        if any(u.startswith(p) for p in ["what is ", "what's ", "can you explain ", "tell me about "]):
            llm_add("user", user)
            try:
                answer = ollama_chat(
                    [
                        {
                            "role": "system",
                            "content": (
                                "You are a cybersecurity assistant. "
                                "Answer clearly and simply. "
                                "If the user asks about a concept like Sysmon, PowerShell, MITRE, or malware, "
                                "explain it directly."
                            )
                        },
                        {"role": "user", "content": user}
                    ],
                    temperature=0.4,
                    force_json=False,
                    timeout_s=120
                )
            except Exception as e:
                answer = f"I couldn't generate an explanation right now. Error: {e}"

            llm_add("assistant", answer)
            st.session_state.messages.append({"role": "assistant", "content": answer})
            st.rerun()
            st.stop()
                    
        investigations = load_investigations()

        before = set(investigations.keys())
        investigations = ensure_defaults(investigations)
        after = set(investigations.keys())
        
        sims = load_simulations()
        sim_cmd, sim_id, sim_agent = parse_sim_command(user)
        
        atomic_cmd, tech, testnum, target_agent = parse_atomic_command(user)

        # Run Atomic Red Team test
        if atomic_cmd == "run":
            started_dt = datetime.now(timezone.utc) - timedelta(minutes=2)
            started_at = started_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            with run_ui:
                with st.spinner("Running Atomic + waiting for Wazuh alerts..."):
                    res = call_runner({
                        "action": "run_atomic",
                        "technique": tech,
                        "test": testnum,
                        "agent": target_agent
                    })
                    detections = poll_for_detections(
                        agentname=target_agent,
                        started_at_iso=started_at,
                        timeout_s=90,
                        interval_s=5
                    )

                    detect_summary, detect_rows = format_alerts(detections)
                    detect_rows = apply_mitre_fallback(detect_rows)
                    st.session_state.last_rows = detect_rows
                    st.session_state.last_kind = "alerts"

                    if detect_rows:
                        narration = ollama_chat(
                            [
                                {"role":"system","content":(
                                    "You are a helpful SOC mentor. Speak naturally.\n"
                                    "Briefly explain what the alerts indicate and what to check next.\n"
                                    "Do NOT claim there were no alerts.\n"
                                    "No JSON."
                                )},
                                {"role":"user","content":(
                                    f"Atomic ran: technique={tech}, test={testnum}, agent={target_agent}\n"
                                    f"Alerts found: {len(detect_rows)}\n"
                                    f"Top 3 alerts: {json.dumps(detect_rows[:3])}"
                                )}
                            ],
                            temperature=0.4,
                            force_json=False
                        )
                    else:
                        narration = (
                            "No Wazuh alerts matched yet. If you’re sure Sysmon triggered, "
                            "try waiting a bit longer, widening the time window, and confirming the agent name matches."
                        )

            run_ui.empty()

            st.session_state.messages.append({
                "role": "assistant",
                "content": (
                    f"Atomic **{tech}** test **{testnum}** on **{target_agent}**\n\n"
                    f"{narration}\n\n{detect_summary}"
                ),
                "table": detect_rows
            })

            st.rerun()
            st.stop()
            
        # If it's just normal conversation, answer without tool routing
        if not looks_like_tool_request(user):
            llm_add("user", user)
            try:
                answer = ollama_chat(get_llm_history(), temperature=0.6, force_json=False, timeout_s=120)
            except Exception as e:
                answer = f"Ollama timed out. Try again or ask for alerts. Error: {e}"
            llm_add("assistant", answer)

            st.session_state.messages.append({"role":"assistant","content": answer})
            st.rerun()
            st.stop()

        # Setup Atomic Red Team
        if atomic_cmd == "setup":
            try:
                res = call_runner({"action": "setup_atomic"})
                reply(
                    content=(
                        "Started Atomic Red Team setup.\n\n"
                        f"Runner response: {res}"
                    )
                )
            except Exception as e:
                reply(content=f"Setup failed: {e}")

        # Help user if they typed an Atomic command in the wrong format
        u = user.lower().strip()
        typed_atomic = u.startswith("run atomic") or u.startswith("setup atomic")

        if typed_atomic and atomic_cmd is None:
            st.session_state.messages.append({
                "role":"assistant",
                "content":"Atomic command format: `run atomic T1218.010 1 on DESKTOP-XXXX` or `setup atomic`."
            })
            st.rerun()
            st.stop()

        if after != before:
            save_investigations(investigations)

        cmd, name = parse_investigation_command(user)
        
        # Allow direct investigation name entry
        if cmd is None:
            key = normalise_name(user)
            if key in investigations:
                cmd, name = "run", user

        # Natural language alias for default investigation
        if cmd is None:
            u = user.lower()

            if "yesterdays" in u:
                u = u.replace("yesterdays", "yesterday")

            if ("suspicious activity" in u) and ("yesterday" in u):
                cmd, name = "run", "yesterday suspicious activity"

        # -----------------------------
        # Investigation actions
        # -----------------------------

        if cmd == "list":
            if not investigations:
                reply = (
                    "No saved investigations yet.\n\n"
                    "You can create one with:\n"
                    "`save investigation <name>` after running a search."
                )
                st.session_state.messages.append(
                    {"role": "assistant", "content": reply}
                )
                st.rerun()
                st.stop()

            rows = []
            for k, v in investigations.items():
                rows.append({
                    "name": k,
                    "limit": v.get("limit"),
                    "time": v.get("time"),
                    "query": v.get("query"),
                    "notes": v.get("notes", "")
                })

            st.session_state.messages.append({
                "role": "assistant",
                "content": f"I found **{len(rows)}** saved investigations:",
                "table": rows
            })
            st.rerun()
            st.stop()

        elif cmd == "run":
            key = normalise_name(name)
            inv = investigations.get(key)

            if not inv:
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": f"I couldn’t find an investigation called **{name}**.\n\nTry `list investigations`."
                })
                st.rerun()
                st.stop()

            final_q = inv["query"]
            if inv.get("time"):
                final_q = f"({final_q}) AND {inv['time']}"

            alerts = search_alerts(
                limit=inv.get("limit", 20),
                query=final_q
            )
            summary, rows = format_alerts(alerts)

            reply = (
                f"Running saved investigation **{key}**.\n\n"
                f"- Time: `{inv.get('time','(none)')}`\n"
                f"- Limit: **{inv.get('limit', 20)}**\n"
                f"- Query: `{inv.get('query')}`\n\n"
                + summary
            )

            st.session_state.messages.append({
                "role": "assistant",
                "content": reply,
                "table": rows
            })
            st.rerun()
            st.stop()

        elif cmd == "delete":
            key = normalise_name(name)

            if key in investigations:
                investigations.pop(key)
                save_investigations(investigations)
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": f"Deleted investigation **{key}**."
                })
            else:
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": f"No investigation called **{name}** found."
                })
            st.rerun()
            st.stop()

        elif cmd == "save":
            key = normalise_name(name)

            if "last_inv" not in st.session_state:
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": (
                        "Run a search first, then save it.\n\n"
                        "I need the last query and time window."
                    )
                })
                st.rerun()
                st.stop()
                
            investigations[key] = st.session_state.last_inv
            investigations[key]["saved_at"] = datetime.utcnow().isoformat() + "Z"
            save_investigations(investigations)

            st.session_state.messages.append({
                "role": "assistant",
                "content": f"Saved investigation **{key}**."
            })
            st.rerun()
            st.stop()
            
        if cmd is not None:
            st.stop()

        # -----------------------------
        # Routed tool flow
        # -----------------------------
        try:
            FAST_COMMANDS = {
                "agents": "list_agents",
                "show mitre": "show_mitre",
                "show mitre attacks": "show_mitre",
                "sysmon alerts": "search_alerts",
                "high alerts": "search_alerts",
            }

            u = user.lower().strip()
            u = re.sub(r"\s+\d{1,3}$", "", u)

            # Fast rule-based routing for common commands
            chart_type, chart_field = parse_chart_command(user)
            if chart_type and chart_field:
                tool = "render_chart"
                args = {
                    "chart_type": chart_type,
                    "field": chart_field,
                    "limit": 100
                }
           
            elif u in FAST_COMMANDS:
                tool = FAST_COMMANDS[u]
                args = {}

                if tool == "search_alerts":
                    args["limit"] = 20
                    if u == "sysmon alerts":
                        args["categories"] = ["sysmon"]
                    elif u == "high alerts":
                        args["severity_min"] = 10
                     
            # Otherwise use LLM routing
            else:
                with st.spinner("Thinking..."):
                    plan = llm_route(user, time_window, agent_filter, min_level, keyword)
                tool = plan.get("tool", "help")
                args = plan.get("args", {}) or {}

            # -----------------------------
            # Execute routed tool
            # -----------------------------

            if tool == "help":
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": (
                        "Try things like:\n\n"
                        "- `agents`\n"
                        "- `show mitre attacks`\n"
                        "- `sysmon alerts`\n"
                        "- `high alerts`\n"
                        "- `run atomic T1059.001 1 on DESKTOP-XXXX`\n"
                    )
                })
                st.rerun()
                st.stop()

            if tool == "list_agents":
                data = list_agents(st.session_state.token)
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": f"I found **{len(data)}** agents. Showing them below.",
                    "table": data
                })
                st.rerun()
                st.stop()

            if tool == "show_mitre":
                tr = window_to_range(time_window)
                agent = args.get("agent")
                mitre_query = "*"
                if agent:
                    mitre_query = f'agent.name:"{agent}"'
                rows = search_alerts(limit=100, query=mitre_query, time_range=tr)
                rows = apply_mitre_fallback(rows)
                mitre_text = top_mitre_summary(rows, top_n=10)
                mitre_rows = [r for r in rows if r.get("mitre_id")]
                if not mitre_rows:
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": "No MITRE-mapped alerts found in that time window."
                    })
                else:
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": mitre_text,
                        "table": mitre_rows[:25]
                    })
                st.rerun()
                st.stop()
                
            if tool == "render_chart":
                limit = int(args.get("limit", 100))
                field = args.get("field", "srcip")
                chart_type = args.get("chart_type", "bar")

                time_range = args_to_time_range(args, time_window, user)

                # Restrict chart data to known Windows agents
                final_q = "(" + " OR ".join([f'agent.name:\"{a}\"' for a in WINDOWS_AGENTS]) + ")"

                rows = search_alerts(limit=limit, query=final_q, time_range=time_range)
                rows = apply_mitre_fallback(rows)

                df = chart_dataframe_from_rows(rows, field=field, top_n=10)
                chart_records = df.to_dict(orient="records")

                st.session_state.messages.append({
                    "role": "assistant",
                    "content": f"Rendered a {chart_type} chart for **{field}** using alerts from **{time_window}**.",
                    "chart": {
                        "chart_type": chart_type,
                        "field": field,
                        "data": chart_records
                    },
                    "table": chart_records
                })

                st.rerun()
                st.stop()

            if tool == "search_alerts":
                limit = int(args.get("limit", 20))
                categories = args.get("categories") or []
                keywords_llm = args.get("keywords") or []
                severity_llm = args.get("severity_min")
                agent_llm = args.get("agent")
                
                # Merge manual UI keyword + LLM keywords
                all_keywords = []
                if keyword.strip():
                    all_keywords.append(keyword.strip())
                all_keywords.extend(keywords_llm)

                final_q = build_lucene_query(
                    categories=categories,
                    keywords=all_keywords,
                    severity_min=severity_llm if severity_llm is not None else (min_level if min_level > 0 else None),
                    agent=agent_llm or (agent_filter.strip() or None)
                )

                time_range = args_to_time_range(args, time_window, user)

                # Also restrict search to allowed Windows agents
                final_q = f'({final_q}) AND (' + " OR ".join([f'agent.name:\"{a}\"' for a in WINDOWS_AGENTS]) + ')'
                
                # Save last search so it can be stored as an investigation later
                st.session_state.last_inv = {
                    "query": final_q,
                    "time": time_window,
                    "limit": limit,
                    "notes": f"Saved from chat: {user}"
                }

                alerts = search_alerts(limit=limit, query=final_q, time_range=time_range)
                summary, rows = format_alerts(alerts)

                st.session_state.last_rows = rows
                st.session_state.last_mitre_ids = collect_recent_mitre_ids(rows)
                st.session_state.last_kind = "alerts"

                mitre_text = top_mitre_summary(rows, top_n=5)

                styled_explanation = explain_alerts_with_style(
                    user_question=user,
                    alerts_rows=rows,
                    response_style=response_style,
                    time_window=time_window
                )

                st.session_state.messages.append({
                    "role": "assistant",
                    "content": styled_explanation + "\n\n---\n\n" + summary + "\n\n" + mitre_text,
                    "table": rows
                })
                st.rerun()
                st.stop()

            if tool == "run_simulation":
                st.session_state.messages.append({"role": "assistant", "content": "run_simulation not implemented yet in this block."})
                st.rerun()
                st.stop()
                
            if tool == "general_chat":
                answer = ollama_chat(
                    [
                        {"role":"system","content":(
                            "You are a friendly cybersecurity assistant. "
                            "Be natural, helpful, and practical. "
                            "If asked for recent news, say you can't browse the live web unless the user provides links/headlines, "
                            "but you can still explain context and typical details."
                        )},
                        {"role":"user","content": user}
                    ],
                    temperature=0.6,
                    force_json=False
                )

                st.session_state.messages.append({"role":"assistant","content": answer})
                st.rerun()
                st.stop()

        except Exception as e:
            st.session_state.messages.append({"role": "assistant", "content": f"Error (route): {e}"})
            st.rerun()
            st.stop()
