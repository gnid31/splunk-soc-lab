#!/usr/bin/env python3
"""
Tạo SOC Investigation Dashboard trên Kibana 8.x
Dùng Lens visualization (modern, supported trong 8.14.3)
Panels: KPI tiles, event distribution, timeline, process table, LSASS, registry, network
"""
import json, requests, sys
from requests.auth import HTTPBasicAuth

KIBANA  = "http://43.228.215.234:5601"
AUTH    = HTTPBasicAuth("elastic", "oScQ3SN32d5tFVOfe3qN")
DV_ID   = "soclab-winlogbeat"          # data view id (winlogbeat-*)
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}

def api(method, path, body=None):
    url = KIBANA + path
    r = requests.request(method, url, auth=AUTH, headers=HEADERS,
                         json=body, timeout=30)
    if r.status_code >= 400:
        print(f"  ERROR {r.status_code}: {r.text[:300]}")
        return None
    return r.json()

def delete_if_exists(obj_type, obj_id):
    api("DELETE", f"/api/saved_objects/{obj_type}/{obj_id}")

# ─── Lens Metric helper ───────────────────────────────────────────────────────
def metric_panel(panel_id, title, kql_filter, color="#54B399",
                 range_colors=None, range_values=None):
    """Single number metric panel with optional KQL filter."""
    filters = ([{"query": kql_filter, "language": "kuery"}]
               if kql_filter else [])

    vis_config = {
        "layerId": "layer1",
        "layerType": "data",
        "metricAccessor": "count-col"
    }
    if range_colors and range_values:
        vis_config["colorMapping"] = {}
        vis_config["palette"] = {
            "type": "palette",
            "name": "status",
            "params": {"stops": [{"color": c, "stop": v}
                                  for c, v in zip(range_colors, range_values)]}
        }

    state = {
        "visualizationType": "lnsMetric",
        "title": title,
        "references": [{"id": DV_ID,
                        "name": "indexpattern-datasource-layer-layer1",
                        "type": "index-pattern"}],
        "state": {
            "visualization": vis_config,
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer1": {
                            "columnOrder": ["count-col"],
                            "columns": {
                                "count-col": {
                                    "label": "Count",
                                    "dataType": "number",
                                    "operationType": "count",
                                    "isBucketed": False,
                                    "scale": "ratio",
                                    "sourceField": "___records___"
                                }
                            }
                        }
                    }
                }
            },
            "filters": filters,
            "query": {"query": "", "language": "kuery"},
            "internalReferences": [],
            "adHocDataViews": {}
        }
    }
    delete_if_exists("lens", panel_id)
    resp = api("POST", f"/api/saved_objects/lens/{panel_id}",
               {"attributes": {k: v for k, v in state.items() if k != "references"},
                "references": state["references"]})
    if resp:
        print(f"  ✓ Metric: {title}")
    return panel_id

# ─── Lens Bar Chart (horizontal, filters aggregation) ────────────────────────
def bar_panel(panel_id, title, filters_list, subtitle="Count"):
    """Horizontal bar chart — each bar is a KQL filter. Works with text fields."""
    filter_buckets = [{"label": label,
                       "input": {"query": kql, "language": "kuery"}}
                      for label, kql in filters_list]
    state = {
        "visualizationType": "lnsXY",
        "title": title,
        "references": [{"id": DV_ID,
                        "name": "indexpattern-datasource-layer-layer1",
                        "type": "index-pattern"}],
        "state": {
            "visualization": {
                "legend": {"isVisible": True, "position": "right"},
                "valueLabels": "inside",
                "fittingFunction": "None",
                "axisTitlesVisibilitySettings": {"x": True, "yLeft": True},
                "tickLabelsVisibilitySettings": {"x": True, "yLeft": True},
                "gridlinesVisibilitySettings": {"x": True, "yLeft": True},
                "layers": [{
                    "layerId": "layer1",
                    "layerType": "data",
                    "accessors": ["count-col"],
                    "xAccessor": "bucket-col",
                    "seriesType": "bar_horizontal",
                    "showGridlines": False
                }]
            },
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer1": {
                            "columnOrder": ["bucket-col", "count-col"],
                            "columns": {
                                "bucket-col": {
                                    "label": "Event Type",
                                    "dataType": "string",
                                    "operationType": "filters",
                                    "isBucketed": True,
                                    "scale": "ordinal",
                                    "params": {"filters": filter_buckets}
                                },
                                "count-col": {
                                    "label": subtitle,
                                    "dataType": "number",
                                    "operationType": "count",
                                    "isBucketed": False,
                                    "scale": "ratio",
                                    "sourceField": "___records___"
                                }
                            }
                        }
                    }
                }
            },
            "filters": [],
            "query": {"query": "", "language": "kuery"},
            "internalReferences": [],
            "adHocDataViews": {}
        }
    }
    delete_if_exists("lens", panel_id)
    resp = api("POST", f"/api/saved_objects/lens/{panel_id}",
               {"attributes": {k: v for k, v in state.items() if k != "references"},
                "references": state["references"]})
    if resp:
        print(f"  ✓ Bar chart: {title}")
    return panel_id

# ─── Lens Area Timeline ───────────────────────────────────────────────────────
def timeline_panel(panel_id, title, filters_list, interval="auto"):
    """Stacked area timeline. X=time, colour=event type via filters."""
    filter_buckets = [{"label": label,
                       "input": {"query": kql, "language": "kuery"}}
                      for label, kql in filters_list]
    state = {
        "visualizationType": "lnsXY",
        "title": title,
        "references": [{"id": DV_ID,
                        "name": "indexpattern-datasource-layer-layer1",
                        "type": "index-pattern"}],
        "state": {
            "visualization": {
                "legend": {"isVisible": True, "position": "bottom"},
                "valueLabels": "hide",
                "fittingFunction": "None",
                "layers": [{
                    "layerId": "layer1",
                    "layerType": "data",
                    "accessors": ["count-col"],
                    "xAccessor": "time-col",
                    "splitAccessor": "filter-col",
                    "seriesType": "area_stacked"
                }]
            },
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer1": {
                            "columnOrder": ["time-col", "filter-col", "count-col"],
                            "columns": {
                                "time-col": {
                                    "label": "@timestamp",
                                    "dataType": "date",
                                    "operationType": "date_histogram",
                                    "sourceField": "@timestamp",
                                    "isBucketed": True,
                                    "scale": "interval",
                                    "params": {"interval": interval,
                                               "includeEmptyRows": True}
                                },
                                "filter-col": {
                                    "label": "Event Type",
                                    "dataType": "string",
                                    "operationType": "filters",
                                    "isBucketed": True,
                                    "scale": "ordinal",
                                    "params": {"filters": filter_buckets}
                                },
                                "count-col": {
                                    "label": "Count",
                                    "dataType": "number",
                                    "operationType": "count",
                                    "isBucketed": False,
                                    "scale": "ratio",
                                    "sourceField": "___records___"
                                }
                            }
                        }
                    }
                }
            },
            "filters": [],
            "query": {"query": "", "language": "kuery"},
            "internalReferences": [],
            "adHocDataViews": {}
        }
    }
    delete_if_exists("lens", panel_id)
    resp = api("POST", f"/api/saved_objects/lens/{panel_id}",
               {"attributes": {k: v for k, v in state.items() if k != "references"},
                "references": state["references"]})
    if resp:
        print(f"  ✓ Timeline: {title}")
    return panel_id

# ─── Saved Search (document table with columns) ───────────────────────────────
def search_panel(panel_id, title, kql, columns, sort_field="@timestamp"):
    """Discover-style document table filtered to specific events."""
    delete_if_exists("search", panel_id)
    body = {
        "attributes": {
            "title": title,
            "description": "",
            "columns": columns,
            "sort": [[sort_field, "desc"]],
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "highlightAll": True,
                    "version": True,
                    "query": {"query": kql, "language": "kuery"},
                    "filter": [],
                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
                })
            }
        },
        "references": [{"id": DV_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                         "type": "index-pattern"}]
    }
    resp = api("POST", f"/api/saved_objects/search/{panel_id}", body)
    if resp:
        print(f"  ✓ Search table: {title}")
    return panel_id

# ─── Build panels ─────────────────────────────────────────────────────────────
print("\n[1/3] Creating visualizations...")

# KPI metrics row
metric_panel("soc-kpi-total",    "📊 Total Events",             "",                "#54B399")
metric_panel("soc-kpi-eid1",     "🔵 EID-1  ProcessCreate",    'event.code: "1"', "#6DCCB1")
metric_panel("soc-kpi-eid10",    "🔴 EID-10 LSASS Access",     'event.code: "10"', "#E7664C")
metric_panel("soc-kpi-eid13",    "🟡 EID-13 Registry Modify",  'event.code: "13"', "#D6BF57")
metric_panel("soc-kpi-eid4104",  "🟣 EID-4104 PowerShell",     'event.code: "4104"', "#AA6556")
metric_panel("soc-kpi-eid3",     "🌐 EID-3  Network Conn",     'event.code: "3"',  "#0077CC")

# Event distribution bar
EID_FILTERS = [
    ("EID-1  ProcessCreate",    'event.code: "1"'),
    ("EID-3  NetworkConnect",   'event.code: "3"'),
    ("EID-10 LSASS Access",     'event.code: "10"'),
    ("EID-11 FileCreate",       'event.code: "11"'),
    ("EID-13 RegistryModify",   'event.code: "13"'),
    ("EID-22 DNSQuery",         'event.code: "22"'),
    ("EID-1102 LogCleared",     'event.code: "1102"'),
    ("EID-4104 PSScriptBlock",  'event.code: "4104"'),
    ("EID-4698 SchedTask",      'event.code: "4698"'),
]
bar_panel("soc-event-dist", "Event Type Distribution (click bar = filter)", EID_FILTERS)

# Timeline
TIMELINE_FILTERS = [
    ("EID-1 ProcessCreate",    'event.code: "1"'),
    ("EID-10 LSASS",           'event.code: "10"'),
    ("EID-13 Registry",        'event.code: "13"'),
    ("EID-4104 PowerShell",    'event.code: "4104"'),
    ("EID-3 Network",          'event.code: "3"'),
]
timeline_panel("soc-timeline", "⏱ Event Timeline (chọn drag để zoom vào khoảng thời gian)", TIMELINE_FILTERS)

# Document tables (each shows actual events with readable columns)
search_panel(
    "soc-processes",
    "🔍 Suspicious Processes (EID-1) — PowerShell / Discovery",
    'event.code: "1" AND message: ("powershell" OR "whoami" OR "systeminfo" OR "ipconfig" OR "netstat" OR "tasklist" OR "schtasks" OR "wscript" OR "cscript" OR "mshta")',
    ["@timestamp", "host.name", "message"],
)
search_panel(
    "soc-lsass",
    "🔴 LSASS Memory Access (EID-10) — Credential Dumping",
    'event.code: "10" AND message: "lsass.exe"',
    ["@timestamp", "host.name", "message"],
)
search_panel(
    "soc-registry",
    "🟡 Registry Persistence (EID-13) — Run Keys / Autorun",
    'event.code: "13" AND message: "\\\\CurrentVersion\\\\Run"',
    ["@timestamp", "host.name", "message"],
)
search_panel(
    "soc-network",
    "🌐 Network Connections (EID-3) — Outbound / C2",
    'event.code: "3"',
    ["@timestamp", "host.name", "message"],
)
search_panel(
    "soc-powershell",
    "🟣 PowerShell ScriptBlocks (EID-4104) — Encoded / Suspicious",
    'event.code: "4104"',
    ["@timestamp", "host.name", "message"],
)
search_panel(
    "soc-filecreate",
    "📁 File Created (EID-11) — Dropper / Staging",
    'event.code: "11"',
    ["@timestamp", "host.name", "message"],
)

# ─── Build dashboard ──────────────────────────────────────────────────────────
print("\n[2/3] Creating dashboard...")

# Grid layout: 48 units wide
# Each panel: gridData = {x, y, w, h, i}
panels = [
    # Row 0: 6 KPI metrics (w=8 each)
    {"id":"soc-kpi-total",   "type":"lens", "x":0,  "y":0,  "w":8,  "h":6},
    {"id":"soc-kpi-eid1",    "type":"lens", "x":8,  "y":0,  "w":8,  "h":6},
    {"id":"soc-kpi-eid10",   "type":"lens", "x":16, "y":0,  "w":8,  "h":6},
    {"id":"soc-kpi-eid13",   "type":"lens", "x":24, "y":0,  "w":8,  "h":6},
    {"id":"soc-kpi-eid4104", "type":"lens", "x":32, "y":0,  "w":8,  "h":6},
    {"id":"soc-kpi-eid3",    "type":"lens", "x":40, "y":0,  "w":8,  "h":6},

    # Row 1: Timeline (full width)
    {"id":"soc-timeline",    "type":"lens", "x":0,  "y":6,  "w":48, "h":14},

    # Row 2: Bar chart (left) + Process table (right)
    {"id":"soc-event-dist",  "type":"lens",   "x":0,  "y":20, "w":18, "h":18},
    {"id":"soc-processes",   "type":"search", "x":18, "y":20, "w":30, "h":18},

    # Row 3: LSASS (left) + Registry (right)
    {"id":"soc-lsass",       "type":"search", "x":0,  "y":38, "w":24, "h":16},
    {"id":"soc-registry",    "type":"search", "x":24, "y":38, "w":24, "h":16},

    # Row 4: Network (left) + PowerShell (right)
    {"id":"soc-network",     "type":"search", "x":0,  "y":54, "w":24, "h":16},
    {"id":"soc-powershell",  "type":"search", "x":24, "y":54, "w":24, "h":16},

    # Row 5: File creates (full width)
    {"id":"soc-filecreate",  "type":"search", "x":0,  "y":70, "w":48, "h":14},
]

panels_json = []
refs        = []
for i, p in enumerate(panels):
    idx = str(i)
    panels_json.append({
        "version":        "8.14.3",
        "type":           p["type"],
        "gridData":       {"x": p["x"], "y": p["y"], "w": p["w"], "h": p["h"], "i": idx},
        "panelIndex":     idx,
        "embeddableConfig": {
            "enhancements": {},
            "hidePanelTitles": False
        },
        "panelRefName": f"panel_{idx}"
    })
    refs.append({"id": p["id"], "name": f"panel_{idx}", "type": p["type"]})

dashboard_id = "soclab-investigation-v2"
delete_if_exists("dashboard", dashboard_id)

body = {
    "attributes": {
        "title": "SOC Lab — Windows Security Investigation",
        "description": (
            "Analyst dashboard: KPI tiles → Timeline → Event Distribution → "
            "Suspicious Processes → LSASS → Registry Persistence → Network → PowerShell. "
            "Dùng time picker để zoom vào attack window. Click bar chart để filter."
        ),
        "panelsJSON":    json.dumps(panels_json),
        "optionsJSON":   json.dumps({
            "useMargins": True,
            "syncColors": True,
            "hidePanelTitles": False,
            "syncTooltips": True
        }),
        "timeRestore":   False,
        "refreshInterval": {"pause": True, "value": 60000},
        "kibanaSavedObjectMeta": {"searchSourceJSON": "{}"}
    },
    "references": refs
}

resp = api("POST", f"/api/saved_objects/dashboard/{dashboard_id}", body)
if resp:
    print(f"  ✓ Dashboard created: {dashboard_id}")
    url = f"{KIBANA}/app/dashboards#/view/{dashboard_id}"
    print(f"\n[3/3] Dashboard URL:\n  {url}\n")
else:
    print("  ✗ Dashboard creation failed")
    sys.exit(1)
