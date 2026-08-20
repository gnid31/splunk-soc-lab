#!/usr/bin/env python3
"""
Import EVTX-ATTACK-SAMPLES → Elasticsearch với proper field extraction.

Mỗi event được parse thành:
  - Top-level ECS-style fields: @timestamp, event.code, host.name, winlog.channel, ...
  - winlog.event_data.*  : tất cả <Data Name="..."> flatten thành field riêng
  - message             : human-readable text (không phải raw XML)
  - evtx.*              : attack metadata (tactic, filename, source)
"""
import sys, json, re, time, requests
from pathlib import Path
from requests.auth import HTTPBasicAuth
import Evtx.Evtx as evtx_lib
import xml.etree.ElementTree as ET

ES    = "http://43.228.215.234:9200"
AUTH  = HTTPBasicAuth("elastic", "oScQ3SN32d5tFVOfe3qN")
INDEX = "evtx-attack-samples"
REPO  = Path.home() / "EVTX-ATTACK-SAMPLES"
BATCH = 400

NS    = "http://schemas.microsoft.com/win/2004/08/events/event"

def tag(name): return f"{{{NS}}}{name}"

# ── Provider-specific EID name tables ────────────────────────────────────────
# Key: lowercase provider name fragment → {eid_str: action_name}
PROVIDER_EID_NAMES = {
    # Sysmon operational events (Microsoft-Windows-Sysmon)
    "sysmon": {
        "1":"ProcessCreate","2":"FileCreationTimeChanged","3":"NetworkConnection",
        "4":"SysmonStateChange","5":"ProcessTerminated","6":"DriverLoaded",
        "7":"ImageLoaded","8":"CreateRemoteThread","9":"RawAccessRead",
        "10":"ProcessAccess","11":"FileCreate","12":"RegistryObjectCreated",
        "13":"RegistryValueSet","14":"RegistryObjectRenamed","15":"FileCreateStreamHash",
        "16":"SysmonConfigChange","17":"PipeCreated","18":"PipeConnected",
        "19":"WmiFilterActivity","20":"WmiConsumerActivity","21":"WmiConsumerFilter",
        "22":"DNSQuery","23":"FileDelete","24":"ClipboardChange","25":"ProcessTampering",
        "26":"FileDeleteDetected","27":"FileBlockExecutable","28":"FileBlockShredding",
        "29":"FileExecutableDetected",
    },
    # Security Auditing (Microsoft-Windows-Security-Auditing)
    "security-auditing": {
        "4624":"Logon","4625":"FailedLogon","4634":"Logoff",
        "4647":"UserInitiatedLogoff","4648":"LogonExplicitCreds",
        "4657":"RegistryValueModified","4662":"ObjectOperation",
        "4663":"ObjectAccess","4670":"PermissionsChanged",
        "4672":"SpecialPrivilegesAssigned","4673":"PrivilegedServiceCalled",
        "4674":"PrivilegedObjectOperation",
        "4688":"ProcessCreated","4689":"ProcessExited",
        "4697":"ServiceInstalled","4698":"ScheduledTaskCreated",
        "4699":"ScheduledTaskDeleted","4700":"ScheduledTaskEnabled",
        "4701":"ScheduledTaskDisabled","4702":"ScheduledTaskUpdated",
        "4703":"TokenRightEnabled","4720":"UserAccountCreated",
        "4722":"UserAccountEnabled","4723":"PasswordChangeAttempt",
        "4724":"PasswordResetAttempt","4725":"UserAccountDisabled",
        "4726":"UserAccountDeleted","4728":"MemberAddedToSecurityGlobal",
        "4732":"MemberAddedToLocalGroup","4735":"LocalGroupChanged",
        "4738":"UserAccountChanged","4741":"ComputerAccountCreated",
        "4742":"ComputerAccountChanged","4743":"ComputerAccountDeleted",
        "4756":"MemberAddedToUniversalGroup",
        "4768":"KerberosTicketRequested","4769":"KerberosServiceTicket",
        "4770":"KerberosTicketRenewed","4771":"KerberosPreauthFailed",
        "4776":"NTLMAuthentication","4778":"SessionReconnect",
        "4779":"SessionDisconnect","4794":"DSRMPasswordSet",
        "4798":"UserLocalGroupEnum","4799":"LocalGroupMember",
        "5136":"DirectoryServiceObjectModified","5137":"DirectoryServiceObjectCreated",
        "5140":"NetworkShareAccess","5141":"NetworkShareObjectDeleted",
        "5145":"NetworkShareCheckAccess","5156":"WFPConnectionAllowed",
        "5158":"WFPBindAllowed","1102":"SecurityAuditLogCleared",
    },
    # Windows RPC (Microsoft-Windows-RPC)
    "windows-rpc": {
        "5":"RPC_ClientCall","6":"RPC_ServerCall",
        "7":"RPC_ClientCallError","8":"RPC_ServerCallError",
    },
    # BITS Client (Microsoft-Windows-Bits-Client)
    "bits-client": {
        "3":"BITSJobCreated","4":"BITSJobModified",
        "5":"BITSJobCompleted","59":"BITSJobTransferring",
        "60":"BITSJobTransferred","61":"BITSJobError",
        "16403":"BITSJobCancelled",
    },
    # RDP / Terminal Services
    "rdpcoretsoperational": {
        "104":"RDPClientActiveConnection","131":"RDPServerConnection",
        "140":"RDPServerConnectionFailed","148":"RDPClientTimezoneInfo",
    },
    "remoteconnectionmanager": {
        "1149":"RDPUserAuthenticated","20":"RDPLogoff","24":"RDPLogoff",
        "25":"RDPReconnect","39":"RDPLogoff",
    },
    # Service Control Manager
    "service control manager": {
        "7034":"ServiceCrashed","7035":"ServiceControlRequest",
        "7036":"ServiceStateChanged","7040":"ServiceStartTypeChanged",
        "7045":"ServiceInstalled",
    },
    # MSI / App install
    "msiinstaller": {
        "1033":"InstallationStarted","1034":"InstallationCompleted",
        "1035":"InstallationSucceeded","1036":"InstallationFailed",
        "1040":"InstallationStarted","1042":"InstallationEnded",
    },
    # PowerShell
    "powershell": {
        "400":"PSEngineLifecycleStart","403":"PSEngineLifecycleStop",
        "600":"PSProviderLifecycle","4100":"PSError",
        "4103":"PSModuleLogging","4104":"PSScriptBlockLogging",
    },
    # EventLog (Microsoft-Windows-Eventlog)
    "eventlog": {
        "104":"SystemLogCleared","1100":"EventLoggingShutdown",
        "1101":"AuditEventsDropped","1102":"SecurityAuditLogCleared",
    },
    # Windows Defender
    "windows defender": {
        "1006":"MalwareDetected","1007":"MalwareActionTaken",
        "1116":"DetectionFound","1117":"ActionTakenOnThreat",
        "1118":"RemediationFailed","1119":"RemediationSucceeded",
    },
    # MSSQL
    "mssqlserver": {
        "18453":"LoginSucceeded","18454":"LoginSucceededPrivileged",
        "18456":"LoginFailed","33205":"AuditEvent",
    },
}

# Fallback: EID-only when no provider match
EID_NAMES_FALLBACK = {
    "104":"SystemLogCleared","1100":"EventLoggingShutdown",
    "1101":"AuditEventsDropped","1102":"AuditLogCleared",
    "1149":"RDPUserAuthenticated","7034":"ServiceCrashed",
    "7035":"ServiceControlRequest","7036":"ServiceStateChanged",
    "7040":"ServiceStartTypeChanged","7045":"ServiceInstalled",
}

# Provider keyword → key in PROVIDER_EID_NAMES (order matters: more specific first)
PROVIDER_KEY_MAP = [
    ("sysmon",                  "sysmon"),
    ("security-auditing",       "security-auditing"),
    ("bits-client",             "bits-client"),
    ("rdpcorets",               "rdpcoretsoperational"),
    ("remoteconnectionmanager", "remoteconnectionmanager"),
    ("service control manager", "service control manager"),
    ("msiinstaller",            "msiinstaller"),
    ("powershell",              "powershell"),
    ("eventlog",                "eventlog"),
    ("windows defender",        "windows defender"),
    ("mssql",                   "mssqlserver"),
    ("windows-rpc",             "windows-rpc"),
    ("microsoft-windows-rpc",   "windows-rpc"),
]

def resolve_action(provider: str, eid: str) -> str:
    """
    Return human-readable action name using provider-aware lookup.
    Falls back to EID-only table, then generic 'EventID-<eid>'.
    """
    prov_lower = provider.lower()
    for fragment, table_key in PROVIDER_KEY_MAP:
        if fragment in prov_lower:
            name = PROVIDER_EID_NAMES[table_key].get(eid)
            if name:
                return name
            break  # provider matched but EID not in that table → fall through
    # Generic fallback
    return EID_NAMES_FALLBACK.get(eid, f"EventID-{eid}")

def parse_timestamp(ts_str):
    """Convert various timestamp formats to ISO8601Z."""
    if not ts_str:
        return "1970-01-01T00:00:00.000Z"
    ts_str = ts_str.strip().rstrip("+00:00")
    ts_str = ts_str.replace(" ", "T")
    # Truncate microseconds to milliseconds
    ts_str = re.sub(r'(\.\d{3})\d*', r'\1', ts_str)
    if not ts_str.endswith("Z"):
        ts_str += "Z"
    return ts_str

def parse_evtx_record(xml_str, tactic, filename, filepath):
    """
    Parse a single EVTX XML record into a flat ES document.
    Returns a dict ready for bulk import.
    """
    root = ET.fromstring(xml_str)

    # ── System fields ──────────────────────────────────────────────────────
    sys_el = root.find(tag("System"))
    event_id = provider = computer = channel = timestamp = ""
    level = task = ""

    if sys_el is not None:
        eid_el  = sys_el.find(tag("EventID"))
        event_id = (eid_el.text or "").strip() if eid_el is not None else ""

        prov_el  = sys_el.find(tag("Provider"))
        provider = prov_el.get("Name", "") if prov_el is not None else ""

        comp_el  = sys_el.find(tag("Computer"))
        computer = (comp_el.text or "").strip() if comp_el is not None else ""

        ch_el    = sys_el.find(tag("Channel"))
        channel  = (ch_el.text or "").strip() if ch_el is not None else ""

        tc_el    = sys_el.find(tag("TimeCreated"))
        if tc_el is not None:
            timestamp = parse_timestamp(
                tc_el.get("SystemTime", "") or tc_el.get("SystemTime", "")
            )

        lv_el = sys_el.find(tag("Level"))
        level = (lv_el.text or "").strip() if lv_el is not None else ""

        task_el = sys_el.find(tag("Task"))
        task = (task_el.text or "").strip() if task_el is not None else ""

    # ── EventData / UserData fields ────────────────────────────────────────
    event_data = {}
    for section_tag in [tag("EventData"), tag("UserData")]:
        section = root.find(section_tag)
        if section is None:
            continue
        # Named <Data Name="..."> elements
        for data_el in section.findall(tag("Data")):
            name  = data_el.get("Name", "").strip()
            value = (data_el.text or "").strip()
            if name and value and value not in ("-", "%%1795", "%%1796"):
                event_data[name] = value
        # Unnamed text content
        if section.text and section.text.strip():
            event_data["_value"] = section.text.strip()[:500]

    # ── Build human-readable message ───────────────────────────────────────
    eid_name = resolve_action(provider, event_id)
    msg_parts = [f"EventID={event_id} ({eid_name}) [{provider}]"]
    if computer:
        msg_parts.append(f"Host={computer}")
    if channel:
        msg_parts.append(f"Channel={channel}")
    # Append all EventData as key=value pairs
    for k, v in event_data.items():
        msg_parts.append(f"{k}={v}")
    human_message = " | ".join(msg_parts)

    # ── Promote common fields for easy KQL ────────────────────────────────
    promoted = {}
    field_map = {
        # Logon events
        "SubjectUserName":    "winlog.user.name",
        "SubjectDomainName":  "winlog.user.domain",
        "TargetUserName":     "winlog.target_user.name",
        "TargetDomainName":   "winlog.target_user.domain",
        "LogonType":          "winlog.logon.type",
        "IpAddress":          "source.ip",
        "WorkstationName":    "source.domain",
        "Workstation":        "source.domain",
        # Process events
        "Image":              "process.executable",
        "CommandLine":        "process.command_line",
        "ParentImage":        "process.parent.executable",
        "ParentCommandLine":  "process.parent.command_line",
        "User":               "winlog.user.name",
        "ProcessId":          "process.pid",
        # Network events
        "DestinationIp":      "destination.ip",
        "DestinationPort":    "destination.port",
        "DestinationHostname":"destination.domain",
        "SourceIp":           "source.ip",
        "SourcePort":         "source.port",
        # Registry events
        "TargetObject":       "registry.path",
        "Details":            "registry.value",
        # File events
        "TargetFilename":     "file.path",
        # LSASS
        "TargetImage":        "winlog.event_data.TargetImage",
        "GrantedAccess":      "winlog.event_data.GrantedAccess",
        "SourceImage":        "winlog.event_data.SourceImage",
        # Auth
        "Status":             "winlog.event_data.Status",
        "SubjectUserSid":     "winlog.user.identifier",
        "ShareName":          "winlog.event_data.ShareName",
    }
    for src, dst in field_map.items():
        if src in event_data:
            promoted[dst] = event_data[src]

    # ── Assemble final document ────────────────────────────────────────────
    doc = {
        # Core
        "@timestamp":         timestamp or "1970-01-01T00:00:00.000Z",
        "event.code":         event_id,
        "event.action":       eid_name,
        "event.provider":     provider,
        "event.severity":     int(level) if level.isdigit() else 0,
        "winlog.channel":     channel,
        "winlog.task":        task,
        "host.name":          computer,
        # Readable message
        "message":            human_message,
        # Full EventData as nested object (still searchable)
        "winlog.event_data":  event_data,
        # Attack metadata
        "evtx.tactic":        tactic,
        "evtx.filename":      filename,
        "evtx.filepath":      str(filepath),
        "evtx.source":        "EVTX-ATTACK-SAMPLES",
        "tags":               ["evtx-sample",
                               tactic.lower().replace(" ", "_")],
    }
    # Merge promoted fields
    doc.update(promoted)

    # Drop empty strings
    doc = {k: v for k, v in doc.items()
           if v != "" and v != [] and v is not None}

    return doc

# ── Bulk import ───────────────────────────────────────────────────────────────
def flush(batch):
    lines = []
    for doc in batch:
        lines.append(json.dumps({"index": {"_index": INDEX}}))
        lines.append(json.dumps(doc, ensure_ascii=False, default=str))
    body = "\n".join(lines) + "\n"
    r = requests.post(f"{ES}/_bulk", auth=AUTH,
                      headers={"Content-Type": "application/x-ndjson"},
                      data=body.encode("utf-8", "replace"),
                      timeout=60)
    resp = r.json()
    ok  = sum(1 for i in resp.get("items", [])
              if i.get("index", {}).get("status", 999) < 400)
    err = len(batch) - ok
    return ok, err

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    # Delete + recreate index with proper mappings
    requests.delete(f"{ES}/{INDEX}", auth=AUTH, timeout=10)
    mapping = {
        "settings": {"number_of_replicas": 0, "number_of_shards": 1},
        "mappings": {
            "properties": {
                "@timestamp":              {"type": "date"},
                "event.code":              {"type": "keyword"},
                "event.action":            {"type": "keyword"},
                "event.provider":          {"type": "keyword"},
                "event.severity":          {"type": "integer"},
                "winlog.channel":          {"type": "keyword"},
                "host.name":               {"type": "keyword"},
                "winlog.user.name":        {"type": "keyword"},
                "winlog.user.domain":      {"type": "keyword"},
                "winlog.target_user.name": {"type": "keyword"},
                "winlog.logon.type":       {"type": "keyword"},
                "process.executable":      {"type": "keyword"},
                "process.command_line":    {"type": "text",
                                           "fields":{"keyword":{"type":"keyword","ignore_above":512}}},
                "process.parent.executable": {"type": "keyword"},
                "source.ip":              {"type": "ip", "ignore_malformed": True},
                "destination.ip":         {"type": "ip", "ignore_malformed": True},
                "destination.port":        {"type": "integer"},
                "registry.path":           {"type": "keyword"},
                "file.path":               {"type": "keyword"},
                "message":                 {"type": "text"},
                "winlog.event_data":       {"type": "object", "dynamic": True},
                "evtx.tactic":             {"type": "keyword"},
                "evtx.filename":           {"type": "keyword"},
                "evtx.filepath":           {"type": "keyword"},
                "evtx.source":             {"type": "keyword"},
                "tags":                    {"type": "keyword"},
            }
        }
    }
    r = requests.put(f"{ES}/{INDEX}", auth=AUTH,
                     headers={"Content-Type": "application/json"},
                     json=mapping, timeout=10)
    print("Index created:", r.json().get("acknowledged"))

    evtx_files = sorted(REPO.rglob("*.evtx"))
    print(f"Importing {len(evtx_files)} EVTX files...\n")

    batch = []
    total_ok = total_err = 0

    for i, fpath in enumerate(evtx_files, 1):
        parts   = fpath.relative_to(REPO).parts
        tactic  = parts[0] if len(parts) > 1 else "Unknown"
        rel     = fpath.relative_to(REPO)
        n_recs  = 0

        try:
            with evtx_lib.Evtx(str(fpath)) as log:
                for record in log.records():
                    try:
                        doc = parse_evtx_record(
                            record.xml(), tactic, fpath.name, rel)
                        batch.append(doc)
                        n_recs += 1
                    except Exception:
                        pass
        except Exception as e:
            print(f"  WARN {fpath.name}: {e}", file=sys.stderr)

        if len(batch) >= BATCH:
            ok, err = flush(batch)
            total_ok  += ok
            total_err += err
            batch = []

        print(f"  [{i:3d}/{len(evtx_files)}] {tactic:<28} "
              f"| {fpath.name:<48} | {n_recs} records")

    if batch:
        ok, err = flush(batch)
        total_ok  += ok
        total_err += err

    time.sleep(3)
    count = (requests.get(f"{ES}/{INDEX}/_count", auth=AUTH, timeout=10)
             .json().get("count", 0))

    print(f"\n{'='*65}")
    print(f"DONE — imported: {total_ok:,}  errors: {total_err}  |  ES count: {count:,}")

    # Tactic summary
    r2 = requests.post(f"{ES}/{INDEX}/_search", auth=AUTH,
                       headers={"Content-Type": "application/json"},
                       json={"size": 0,
                             "aggs": {"t": {"terms": {"field": "evtx.tactic",
                                                      "size": 20}}}},
                       timeout=10)
    print("\nTactic distribution:")
    for b in r2.json()["aggregations"]["t"]["buckets"]:
        print(f"  {b['key']:<35}: {b['doc_count']:>6,} events")

if __name__ == "__main__":
    main()
