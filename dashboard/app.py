"""
NETWATCH Dashboard Application.

Phase 11 - Dashboard

This module provides a local Flask dashboard that visualizes
results produced by the NETWATCH command-line application.

The dashboard is read-only. It does not perform network scans,
modify firewall rules, modify routing tables, or initiate security
testing.

It is designed to run inside the NETWATCH process so that the
dashboard can display the current session state.
"""

from __future__ import annotations

import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Callable

from flask import Flask, jsonify, render_template, send_file


PROJECT_ROOT = Path(__file__).resolve().parent.parent

TOPOLOGY_IMAGE = (
    PROJECT_ROOT
    / "reports_output"
    / "network_topology.png"
)


def _safe_value(value: Any) -> Any:
    """
    Convert common NETWATCH objects into JSON-safe values.
    """

    if value is None:
        return None

    if isinstance(value, (str, int, float, bool)):
        return value

    if is_dataclass(value):
        return _safe_value(asdict(value))

    if isinstance(value, dict):
        return {
            str(key): _safe_value(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [
            _safe_value(item)
            for item in value
        ]

    if hasattr(value, "to_dict"):
        try:
            return _safe_value(value.to_dict())
        except Exception:
            pass

    if hasattr(value, "__dict__"):
        try:
            return {
                str(key): _safe_value(item)
                for key, item in vars(value).items()
                if not key.startswith("_")
            }
        except Exception:
            pass

    return str(value)


def _get_value(
    item: Any,
    *names: str,
    default: Any = None,
) -> Any:
    """
    Read a value from an object or dictionary.
    """

    if item is None:
        return default

    for name in names:
        if isinstance(item, dict):
            if name in item:
                return item[name]

        else:
            if hasattr(item, name):
                return getattr(item, name)

    return default


def _get_collection(
    item: Any,
    *names: str,
) -> list:
    """
    Return a collection attribute as a list.
    """

    value = _get_value(
        item,
        *names,
        default=[],
    )

    if value is None:
        return []

    if isinstance(value, (list, tuple, set)):
        return list(value)

    return []


def _extract_alerts(ids_result: Any) -> list[dict]:
    """
    Convert IDS alerts into dashboard-friendly records.
    """

    alerts = _get_collection(
        ids_result,
        "alerts",
    )

    output = []

    for alert in alerts:
        output.append(
            {
                "alert_id": _get_value(
                    alert,
                    "alert_id",
                    "id",
                    default="N/A",
                ),
                "timestamp": str(
                    _get_value(
                        alert,
                        "timestamp",
                        default="N/A",
                    )
                ),
                "source": _get_value(
                    alert,
                    "source",
                    "source_ip",
                    default="N/A",
                ),
                "destination": _get_value(
                    alert,
                    "destination",
                    "destination_ip",
                    default="N/A",
                ),
                "type": _get_value(
                    alert,
                    "detection_type",
                    "alert_type",
                    "type",
                    default="Unknown",
                ),
                "severity": str(
                    _get_value(
                        alert,
                        "severity",
                        default="INFO",
                    )
                ).upper(),
                "description": _get_value(
                    alert,
                    "description",
                    default="",
                ),
                "evidence": _get_value(
                    alert,
                    "evidence",
                    default="",
                ),
                "recommended_action": _get_value(
                    alert,
                    "recommended_action",
                    default="",
                ),
            }
        )

    return output


def _extract_devices(devices: Any) -> list[dict]:
    """
    Convert network discovery results into dashboard records.
    """

    if not devices:
        return []

    output = []

    for device in devices:
        output.append(
            {
                "ip": _get_value(
                    device,
                    "ip_address",
                    "ip",
                    default="N/A",
                ),
                "hostname": _get_value(
                    device,
                    "hostname",
                    default="Unknown",
                ),
                "mac": _get_value(
                    device,
                    "mac_address",
                    "mac",
                    default="N/A",
                ),
                "status": str(
                    _get_value(
                        device,
                        "status",
                        default="UNKNOWN",
                    )
                ).upper(),
                "response_time": _get_value(
                    device,
                    "response_time_ms",
                    "response_time",
                    default=None,
                ),
            }
        )

    return output


def _extract_ports(port_result: Any) -> list[dict]:
    """
    Convert port scanner results into dashboard records.
    """

    if port_result is None:
        return []

    results = _get_collection(
        port_result,
        "results",
    )

    output = []

    for item in results:
        output.append(
            {
                "port": _get_value(
                    item,
                    "port",
                    default="N/A",
                ),
                "state": str(
                    _get_value(
                        item,
                        "state",
                        default="UNKNOWN",
                    )
                ).upper(),
                "service": _get_value(
                    item,
                    "service",
                    "service_name",
                    default="Unknown",
                ),
            }
        )

    return output


def _extract_traffic(traffic_result: Any) -> dict:
    """
    Convert traffic analysis results into dashboard statistics.
    """

    if traffic_result is None:
        return {
            "packet_count": 0,
            "total_bytes": 0,
            "protocols": {},
            "top_talkers": [],
        }

    packet_count = _get_value(
        traffic_result,
        "packet_count",
        "total_packets",
        default=0,
    )

    total_bytes = _get_value(
        traffic_result,
        "total_bytes",
        "bytes",
        default=0,
    )

    protocol_counts = _get_value(
        traffic_result,
        "protocol_counts",
        "protocol_distribution",
        "protocols",
        default={},
    )

    if not isinstance(protocol_counts, dict):
        protocol_counts = {}

    top_talkers = _get_value(
        traffic_result,
        "top_talkers",
        default=[],
    )

    if not isinstance(top_talkers, (list, tuple)):
        top_talkers = []

    return {
        "packet_count": packet_count or 0,
        "total_bytes": total_bytes or 0,
        "protocols": _safe_value(protocol_counts),
        "top_talkers": _safe_value(top_talkers),
    }


def _extract_firewall_findings(
    firewall_result: Any,
) -> list[dict]:
    """
    Convert firewall findings into dashboard records.
    """

    if firewall_result is None:
        return []

    findings = _get_collection(
        firewall_result,
        "findings",
    )

    output = []

    for finding in findings:
        output.append(
            {
                "finding_id": _get_value(
                    finding,
                    "finding_id",
                    "id",
                    default="N/A",
                ),
                "severity": str(
                    _get_value(
                        finding,
                        "severity",
                        default="INFO",
                    )
                ).upper(),
                "title": _get_value(
                    finding,
                    "title",
                    "description",
                    default="Firewall observation",
                ),
                "recommendation": _get_value(
                    finding,
                    "recommendation",
                    default="",
                ),
            }
        )

    return output


def _extract_discovery_data(
    discovery_result: Any,
) -> tuple[list[Any], str | None]:
    """
    Extract discovered devices and network scope from the
    current NETWATCH discovery result.

    Supports both the current NetworkDiscovery result structure
    and older dictionary/object layouts.
    """

    if discovery_result is None:
        return [], None

    if isinstance(discovery_result, (list, tuple, set)):
        return list(discovery_result), None

    devices = _get_value(
        discovery_result,
        "devices",
        "discovered_devices",
        "hosts",
        "results",
        default=None,
    )

    if devices is None:
        if isinstance(discovery_result, dict):
            devices = discovery_result.get(
                "discovery",
                [],
            )

    if devices is None:
        devices = []

    if not isinstance(
        devices,
        (list, tuple, set),
    ):
        devices = []

    network = _get_value(
        discovery_result,
        "network",
        "network_cidr",
        "target_network",
        "scope",
        default=None,
    )

    return list(devices), network


def build_dashboard_state() -> dict:
    """
    Build dashboard state from the currently running NETWATCH process.

    NETWATCH executes main.py directly, so its module is available as
    __main__. This allows the web dashboard to visualize the same
    in-memory session state used by the CLI.
    """

    application = sys.modules.get("__main__")

    if application is None:
        return {
            "application": {
                "name": "NETWATCH",
                "version": "Unknown",
            },
            "assessment": {
                "authorized_assessment_only": True,
                "network": "No discovery performed",
            },
            "summary": {
                "devices_discovered": 0,
                "open_ports": 0,
                "network_alerts": 0,
                "high_severity_alerts": 0,
                "traffic_packets": 0,
                "traffic_bytes": 0,
                "firewall_findings": 0,
            },
            "devices": [],
            "ports": [],
            "alerts": [],
            "severity_counts": {
                "INFO": 0,
                "LOW": 0,
                "MEDIUM": 0,
                "HIGH": 0,
                "CRITICAL": 0,
            },
            "traffic": {
                "packet_count": 0,
                "total_bytes": 0,
                "protocols": {},
                "top_talkers": [],
            },
            "firewall_findings": [],
            "topology": {
                "available": False,
                "image_available": TOPOLOGY_IMAGE.exists(),
                "nodes": 0,
                "connections": 0,
            },
        }

    # ------------------------------------------------------------------
    # Current NETWATCH session state
    # ------------------------------------------------------------------

    discovery_result = getattr(
        application,
        "last_discovery_result",
        None,
    )

    # Backward-compatible support for separate discovery variables.
    legacy_devices = getattr(
        application,
        "last_discovery_devices",
        None,
    )

    legacy_network = getattr(
        application,
        "last_discovery_network",
        None,
    )

    discovered_devices, discovered_network = (
        _extract_discovery_data(
            discovery_result,
        )
    )

    if not discovered_devices and legacy_devices:
        discovered_devices = legacy_devices

    network = (
        discovered_network
        or legacy_network
    )

    port_result = getattr(
        application,
        "last_port_scan_result",
        None,
    )

    traffic_result = getattr(
        application,
        "last_traffic_result",
        None,
    )

    ids_result = getattr(
        application,
        "last_ids_result",
        None,
    )

    firewall_result = getattr(
        application,
        "last_firewall_result",
        None,
    )

    topology_result = getattr(
        application,
        "last_topology_result",
        None,
    )

    configuration = getattr(
        application,
        "configuration",
        {},
    )

    authorized_only = True

    try:
        authorized_only = bool(
            configuration[
                "application"
            ][
                "authorized_assessment_only"
            ]
        )
    except (
        KeyError,
        TypeError,
        AttributeError,
    ):
        pass

    # ------------------------------------------------------------------
    # Normalize module results
    # ------------------------------------------------------------------

    device_records = _extract_devices(
        discovered_devices,
    )

    port_records = _extract_ports(
        port_result,
    )

    alerts = _extract_alerts(
        ids_result,
    )

    traffic = _extract_traffic(
        traffic_result,
    )

    firewall_findings = _extract_firewall_findings(
        firewall_result,
    )

    severity_counts = {
        "INFO": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    for alert in alerts:
        severity = alert["severity"]

        if severity in severity_counts:
            severity_counts[severity] += 1

    topology_available = topology_result is not None

    # ------------------------------------------------------------------
    # Dashboard state
    # ------------------------------------------------------------------

    return {
        "application": {
            "name": getattr(
                application,
                "APPLICATION_NAME",
                "NETWATCH",
            ),
            "version": getattr(
                application,
                "APPLICATION_VERSION",
                "Unknown",
            ),
        },
        "assessment": {
            "authorized_assessment_only": authorized_only,
            "network": network or "No discovery performed",
        },
        "summary": {
            "devices_discovered": len(
                device_records
            ),
            "open_ports": sum(
                1
                for port in port_records
                if port["state"] == "OPEN"
            ),
            "network_alerts": len(alerts),
            "high_severity_alerts": (
                severity_counts["HIGH"]
                + severity_counts["CRITICAL"]
            ),
            "traffic_packets": traffic[
                "packet_count"
            ],
            "traffic_bytes": traffic[
                "total_bytes"
            ],
            "firewall_findings": len(
                firewall_findings
            ),
        },
        "devices": device_records,
        "ports": port_records,
        "alerts": alerts,
        "severity_counts": severity_counts,
        "traffic": traffic,
        "firewall_findings": firewall_findings,
        "topology": {
            "available": topology_available,
            "image_available": TOPOLOGY_IMAGE.exists(),
            "nodes": (
                _get_value(
                    topology_result,
                    "node_count",
                    default=0,
                )
                if topology_result
                else 0
            ),
            "connections": (
                _get_value(
                    topology_result,
                    "edge_count",
                    "connection_count",
                    default=0,
                )
                if topology_result
                else 0
            ),
        },
    }


def create_app(
    state_provider: Callable[[], dict] | None = None,
) -> Flask:
    """
    Create the NETWATCH Flask application.
    """

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    provider = (
        state_provider
        if state_provider is not None
        else build_dashboard_state
    )

    @app.get("/")
    def dashboard():
        return render_template(
            "index.html",
        )

    @app.get("/api/state")
    def dashboard_state():
        try:
            state = provider()

            return jsonify(
                _safe_value(state)
            )

        except Exception as exc:
            return jsonify(
                {
                    "error": str(exc),
                }
            ), 500

    @app.get("/topology-image")
    def topology_image():
        if not TOPOLOGY_IMAGE.exists():
            return (
                jsonify(
                    {
                        "error": (
                            "No topology image has been "
                            "exported yet."
                        )
                    }
                ),
                404,
            )

        return send_file(
            TOPOLOGY_IMAGE,
            mimetype="image/png",
        )

    return app


def run_dashboard(
    host: str = "127.0.0.1",
    port: int = 5000,
    state_provider: Callable[[], dict] | None = None,
) -> None:
    """
    Run the dashboard server.

    This function is intended for local use only.
    """

    dashboard_app = create_app(
        state_provider=state_provider,
    )

    dashboard_app.run(
        host=host,
        port=port,
        debug=False,
        use_reloader=False,
        threaded=True,
    )


# ----------------------------------------------------------------------
# Module-level Flask application
# ----------------------------------------------------------------------
#
# main.py imports:
#
#     from dashboard.app import app
#
# Therefore the module must expose an application object named "app".
#
# The application is created without starting the server. This makes
# it safe for both direct imports from main.py and Flask-style testing.
# ----------------------------------------------------------------------

app = create_app()


if __name__ == "__main__":
    run_dashboard()