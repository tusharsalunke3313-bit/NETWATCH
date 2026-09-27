"""
NETWATCH Phase 13 - Automated PDF Security Assessment Report.

This module generates professional PDF reports from the consolidated
Security Assessment Engine result.

The report is observational. It does not claim that findings prove
malicious activity or malicious intent.
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class PDFReportError(Exception):
    """Raised when PDF report generation fails."""


SEVERITIES = (
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
)


class PDFReportGenerator:
    """Generate a professional PDF security assessment report."""

    REPORT_TITLE = "NETWORK SECURITY ASSESSMENT REPORT"
    REPORT_SUBTITLE = (
        "NETWATCH — Network Monitoring & Security Platform"
    )

    def __init__(
        self,
        output_directory: str | Path = "reports_output",
    ) -> None:
        self.output_directory = Path(output_directory)
        self.output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.styles = self._build_styles()

    # ==========================================================
    # PUBLIC API
    # ==========================================================

    def generate(
        self,
        assessment: Any,
        filename: str | None = None,
    ) -> Path:
        """Generate a PDF report from assessment data."""

        data = self._normalize_assessment(assessment)

        if not data:
            raise PDFReportError(
                "Assessment data cannot be empty."
            )

        assessment_id = str(
            data.get(
                "assessment_id",
                "UNKNOWN",
            )
        )

        if filename is None:
            safe_id = self._safe_filename_part(
                assessment_id
            )

            filename = (
                "netwatch_security_assessment_"
                f"{safe_id}.pdf"
            )

        output_path = (
            self.output_directory / filename
        )

        if output_path.suffix.lower() != ".pdf":
            output_path = output_path.with_suffix(".pdf")

        try:
            document = SimpleDocTemplate(
                str(output_path),
                pagesize=A4,
                rightMargin=15 * mm,
                leftMargin=15 * mm,
                topMargin=15 * mm,
                bottomMargin=15 * mm,
                title=self.REPORT_TITLE,
                author="NETWATCH",
                subject="Network Security Assessment",
            )

            story = self._build_story(data)

            document.build(
                story,
                onFirstPage=self._draw_footer,
                onLaterPages=self._draw_footer,
            )

        except Exception as exc:
            raise PDFReportError(
                f"Failed to generate PDF report: {exc}"
            ) from exc

        if not output_path.exists():
            raise PDFReportError(
                "PDF generation completed but the output "
                "file was not created."
            )

        if output_path.stat().st_size == 0:
            raise PDFReportError(
                "PDF generation created an empty file."
            )

        return output_path

    # ==========================================================
    # DATA NORMALIZATION
    # ==========================================================

    def _normalize_assessment(
        self,
        assessment: Any,
    ) -> dict[str, Any]:
        if assessment is None:
            return {}

        if is_dataclass(assessment):
            data = asdict(assessment)

        elif isinstance(assessment, Mapping):
            data = dict(assessment)

        elif hasattr(assessment, "to_dict"):
            data = assessment.to_dict()

        else:
            raise PDFReportError(
                "Assessment must be a mapping, dataclass, "
                "or object with to_dict()."
            )

        if not isinstance(data, dict):
            raise PDFReportError(
                "Assessment serialization must produce "
                "a mapping."
            )

        return data

    # ==========================================================
    # STYLES
    # ==========================================================

    def _build_styles(
        self,
    ) -> dict[str, ParagraphStyle]:

        base = getSampleStyleSheet()

        return {
            "cover_title": ParagraphStyle(
                "CoverTitle",
                parent=base["Title"],
                fontName="Helvetica-Bold",
                fontSize=22,
                leading=28,
                alignment=TA_CENTER,
                spaceAfter=12,
            ),
            "cover_subtitle": ParagraphStyle(
                "CoverSubtitle",
                parent=base["Normal"],
                fontName="Helvetica",
                fontSize=11,
                leading=16,
                alignment=TA_CENTER,
                spaceAfter=20,
            ),
            "section": ParagraphStyle(
                "Section",
                parent=base["Heading1"],
                fontName="Helvetica-Bold",
                fontSize=15,
                leading=19,
                spaceBefore=6,
                spaceAfter=10,
            ),
            "subsection": ParagraphStyle(
                "Subsection",
                parent=base["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=11,
                leading=14,
                spaceBefore=8,
                spaceAfter=6,
            ),
            "body": ParagraphStyle(
                "Body",
                parent=base["BodyText"],
                fontName="Helvetica",
                fontSize=9,
                leading=13,
                spaceAfter=5,
            ),
            "small": ParagraphStyle(
                "Small",
                parent=base["BodyText"],
                fontName="Helvetica",
                fontSize=7.5,
                leading=10,
                spaceAfter=3,
            ),
            "table_header": ParagraphStyle(
                "TableHeader",
                parent=base["BodyText"],
                fontName="Helvetica-Bold",
                fontSize=8,
                leading=10,
            ),
            "table_body": ParagraphStyle(
                "TableBody",
                parent=base["BodyText"],
                fontName="Helvetica",
                fontSize=7.5,
                leading=10,
            ),
            "note": ParagraphStyle(
                "Note",
                parent=base["BodyText"],
                fontName="Helvetica-Oblique",
                fontSize=8,
                leading=12,
                spaceBefore=5,
                spaceAfter=8,
            ),
        }

    # ==========================================================
    # STORY
    # ==========================================================

    def _build_story(
        self,
        data: dict[str, Any],
    ) -> list[Any]:

        story: list[Any] = []

        story.extend(
            self._cover_page(data)
        )

        story.extend(
            self._executive_summary(data)
        )

        story.extend(
            self._assessment_overview(data)
        )

        story.extend(
            self._network_overview(data)
        )

        story.extend(
            self._devices_section(data)
        )

        story.extend(
            self._ports_section(data)
        )

        story.extend(
            self._dns_section(data)
        )

        story.extend(
            self._http_section(data)
        )

        story.extend(
            self._traffic_section(data)
        )

        story.extend(
            self._ids_section(data)
        )

        story.extend(
            self._firewall_section(data)
        )

        story.extend(
            self._topology_section(data)
        )

        story.extend(
            self._findings_section(data)
        )

        story.extend(
            self._severity_section(data)
        )

        story.extend(
            self._recommendations_section(data)
        )

        story.extend(
            self._notes_section(data)
        )

        story.extend(
            self._technical_appendix(data)
        )

        return story

    # ==========================================================
    # COVER
    # ==========================================================

    def _cover_page(
        self,
        data: dict[str, Any],
    ) -> list[Any]:

        assessment_id = self._text(
            data.get(
                "assessment_id",
                "Unknown",
            )
        )

        timestamp = self._text(
            data.get(
                "timestamp",
                "Unknown",
            )
        )

        scope = self._text(
            data.get(
                "scope",
                "Not specified",
            )
        )

        return [
            Spacer(1, 35 * mm),

            Paragraph(
                self.REPORT_TITLE,
                self.styles["cover_title"],
            ),

            Paragraph(
                self.REPORT_SUBTITLE,
                self.styles["cover_subtitle"],
            ),

            Spacer(1, 15 * mm),

            HRFlowable(
                width="80%",
                thickness=1,
                color=colors.HexColor("#555555"),
                hAlign="CENTER",
            ),

            Spacer(1, 12 * mm),

            Paragraph(
                "<b>Assessment ID:</b> "
                + self._escape(assessment_id),
                self.styles["body"],
            ),

            Paragraph(
                "<b>Assessment Date/Time:</b> "
                + self._escape(timestamp),
                self.styles["body"],
            ),

            Paragraph(
                "<b>Assessment Scope:</b> "
                + self._escape(scope),
                self.styles["body"],
            ),

            Spacer(1, 15 * mm),

            Paragraph(
                "Authorized security assessment only.",
                self.styles["note"],
            ),

            Paragraph(
                "This report presents technical observations, "
                "security findings, and defensive recommendations. "
                "Findings are not proof of malicious activity or "
                "malicious intent.",
                self.styles["note"],
            ),

            PageBreak(),
        ]

    # ==========================================================
    # EXECUTIVE SUMMARY
    # ==========================================================

    def _executive_summary(
        self,
        data: dict[str, Any],
    ) -> list[Any]:

        summary = self._mapping(
            data.get("finding_summary")
        )

        total = summary.get(
            "total",
            self._calculate_total(summary),
        )

        rows = [
            [
                self._paragraph(
                    "Metric",
                    "table_header",
                ),
                self._paragraph(
                    "Value",
                    "table_header",
                ),
            ],
            [
                self._paragraph(
                    "Discovered Devices",
                    "table_body",
                ),
                self._paragraph(
                    str(
                        len(
                            self._sequence(
                                data.get(
                                    "discovered_devices"
                                )
                            )
                        )
                    ),
                    "table_body",
                ),
            ],
            [
                self._paragraph(
                    "Open Ports",
                    "table_body",
                ),
                self._paragraph(
                    str(
                        len(
                            self._sequence(
                                data.get(
                                    "open_ports"
                                )
                            )
                        )
                    ),
                    "table_body",
                ),
            ],
            [
                self._paragraph(
                    "IDS Alerts",
                    "table_body",
                ),
                self._paragraph(
                    str(
                        len(
                            self._sequence(
                                data.get(
                                    "ids_alerts"
                                )
                            )
                        )
                    ),
                    "table_body",
                ),
            ],
            [
                self._paragraph(
                    "Firewall Findings",
                    "table_body",
                ),
                self._paragraph(
                    str(
                        len(
                            self._sequence(
                                data.get(
                                    "firewall_findings"
                                )
                            )
                        )
                    ),
                    "table_body",
                ),
            ],
            [
                self._paragraph(
                    "Total Findings",
                    "table_body",
                ),
                self._paragraph(
                    str(total),
                    "table_body",
                ),
            ],
        ]

        return [
            Paragraph(
                "1. Executive Summary",
                self.styles["section"],
            ),

            Paragraph(
                "NETWATCH consolidated the available network "
                "discovery, port scanning, DNS, HTTP/HTTPS, "
                "traffic, IDS, firewall, and topology observations "
                "into this assessment report.",
                self.styles["body"],
            ),

            self._table(
                rows,
                [85 * mm, 45 * mm],
            ),

            Spacer(1, 5 * mm),

            Paragraph(
                "The report intentionally avoids an unexplained "
                "single security score. Severity counts and "
                "individual observations are presented so that "
                "the assessment can be reviewed in context.",
                self.styles["note"],
            ),
        ]

    # ==========================================================
    # ASSESSMENT OVERVIEW
    # ==========================================================

    def _assessment_overview(
        self,
        data: dict[str, Any],
    ) -> list[Any]:

        return [
            Paragraph(
                "2. Assessment Overview",
                self.styles["section"],
            ),

            self._key_value_table(
                [
                    (
                        "Assessment ID",
                        data.get(
                            "assessment_id",
                            "Unknown",
                        ),
                    ),
                    (
                        "Assessment Date/Time",
                        data.get(
                            "timestamp",
                            "Unknown",
                        ),
                    ),
                    (
                        "Assessment Scope",
                        data.get(
                            "scope",
                            "Not specified",
                        ),
                    ),
                ]
            ),
        ]

    # ==========================================================
    # NETWORK OVERVIEW
    # ==========================================================

    def _network_overview(
        self,
        data: dict[str, Any],
    ) -> list[Any]:

        devices = self._sequence(
            data.get("discovered_devices")
        )

        ports = self._sequence(
            data.get("open_ports")
        )

        services = self._sequence(
            data.get("detected_services")
        )

        return [
            Paragraph(
                "3. Network Overview",
                self.styles["section"],
            ),

            self._key_value_table(
                [
                    (
                        "Devices Discovered",
                        len(devices),
                    ),
                    (
                        "Open Ports",
                        len(ports),
                    ),
                    (
                        "Detected Services",
                        len(services),
                    ),
                    (
                        "Network Alerts",
                        len(
                            self._sequence(
                                data.get(
                                    "ids_alerts"
                                )
                            )
                        ),
                    ),
                ]
            ),
        ]

    # ==========================================================
    # DEVICES
    # ==========================================================

    def _devices_section(
        self,
        data: dict[str, Any],
    ) -> list[Any]:

        devices = self._sequence(
            data.get("discovered_devices")
        )

        story = [
            Paragraph(
                "4. Discovered Devices",
                self.styles["section"],
            )
        ]

        if not devices:
            story.append(
                Paragraph(
                    "No discovered devices were available "
                    "in this assessment.",
                    self.styles["body"],
                )
            )
            return story

        rows = [
            [
                self._paragraph(
                    "IP Address",
                    "table_header",
                ),
                self._paragraph(
                    "Hostname",
                    "table_header",
                ),
                self._paragraph(
                    "MAC",
                    "table_header",
                ),
                self._paragraph(
                    "Status",
                    "table_header",
                ),
            ]
        ]

        for device in devices:
            item = self._mapping(device)

            rows.append(
                [
                    self._paragraph(
                        self._text(
                            item.get("ip")
                        ),
                        "table_body",
                    ),
                    self._paragraph(
                        self._text(
                            item.get("hostname")
                        ),
                        "table_body",
                    ),
                    self._paragraph(
                        self._text(
                            item.get("mac")
                        ),
                        "table_body",
                    ),
                    self._paragraph(
                        self._text(
                            item.get("status")
                        ),
                        "table_body",
                    ),
                ]
            )

        story.append(
            self._table(
                rows,
                [
                    42 * mm,
                    48 * mm,
                    48 * mm,
                    22 * mm,
                ],
            )
        )

        return story

    # ==========================================================
    # PORTS
    # ==========================================================

    def _ports_section(
        self,
        data: dict[str, Any],
    ) -> list[Any]:

        ports = self._sequence(
            data.get("open_ports")
        )

        services = self._sequence(
            data.get("detected_services")
        )

        story = [
            Paragraph(
                "5. Port Scan Results & Service Information",
                self.styles["section"],
            )
        ]

        if ports:
            rows = [
                [
                    self._paragraph(
                        "Port",
                        "table_header",
                    ),
                    self._paragraph(
                        "State",
                        "table_header",
                    ),
                    self._paragraph(
                        "Service",
                        "table_header",
                    ),
                ]
            ]

            for port in ports:
                item = self._mapping(port)

                if item:
                    port_number = item.get(
                        "port",
                        item.get(
                            "number",
                            "",
                        ),
                    )

                    state = item.get(
                        "state",
                        "OPEN",
                    )

                    service = item.get(
                        "service",
                        item.get(
                            "service_name",
                            "",
                        ),
                    )

                else:
                    port_number = port
                    state = "OPEN"
                    service = ""

                rows.append(
                    [
                        self._paragraph(
                            self._text(
                                port_number
                            ),
                            "table_body",
                        ),
                        self._paragraph(
                            self._text(state),
                            "table_body",
                        ),
                        self._paragraph(
                            self._text(
                                service
                            ),
                            "table_body",
                        ),
                    ]
                )

            story.append(
                self._table(
                    rows,
                    [
                        35 * mm,
                        45 * mm,
                        80 * mm,
                    ],
                )
            )

        else:
            story.append(
                Paragraph(
                    "No open ports were recorded.",
                    self.styles["body"],
                )
            )

        if services:
            story.append(
                Paragraph(
                    "Detected Services",
                    self.styles["subsection"],
                )
            )

            for service in services:
                item = self._mapping(service)

                story.append(
                    Paragraph(
                        self._escape(
                            self._format_mapping(item)
                        ),
                        self.styles["small"],
                    )
                )

        return story

    # ==========================================================
    # DNS
    # ==========================================================

    def _dns_section(
        self,
        data: dict[str, Any],
    ) -> list[Any]:

        findings = self._sequence(
            data.get("dns_findings")
        )

        story = [
            Paragraph(
                "6. DNS Analysis",
                self.styles["section"],
            )
        ]

        if not findings:
            story.append(
                Paragraph(
                    "No DNS observations were recorded.",
                    self.styles["body"],
                )
            )
            return story

        for finding in findings:
            story.append(
                Paragraph(
                    self._escape(
                        self._format_item(
                            finding
                        )
                    ),
                    self.styles["small"],
                )
            )

        return story

    # ==========================================================
    # HTTP
    # ==========================================================

    def _http_section(
        self,
        data: dict[str, Any],
    ) -> list[Any]:

        findings = self._sequence(
            data.get("http_findings")
        )

        story = [
            Paragraph(
                "7. HTTP/HTTPS Analysis",
                self.styles["section"],
            )
        ]

        if not findings:
            story.append(
                Paragraph(
                    "No HTTP/HTTPS observations were recorded.",
                    self.styles["body"],
                )
            )
            return story

        for finding in findings:
            story.append(
                Paragraph(
                    self._escape(
                        self._format_item(
                            finding
                        )
                    ),
                    self.styles["small"],
                )
            )

        return story

    # ==========================================================
    # TRAFFIC
    # ==========================================================

    def _traffic_section(
        self,
        data: dict[str, Any],
    ) -> list[Any]:

        findings = self._sequence(
            data.get("traffic_findings")
        )

        story = [
            Paragraph(
                "8. Traffic Analysis",
                self.styles["section"],
            )
        ]

        traffic = self._mapping(
            data.get("traffic")
        )

        if traffic:
            story.append(
                self._key_value_table(
                    [
                        (
                            "Packet Count",
                            traffic.get(
                                "packet_count",
                                traffic.get(
                                    "total_packets",
                                    0,
                                ),
                            ),
                        ),
                        (
                            "Total Bytes",
                            traffic.get(
                                "total_bytes",
                                0,
                            ),
                        ),
                    ]
                )
            )

        if not findings:
            story.append(
                Paragraph(
                    "No additional traffic findings were "
                    "recorded in the assessment.",
                    self.styles["body"],
                )
            )

        else:
            for finding in findings:
                story.append(
                    Paragraph(
                        self._escape(
                            self._format_item(
                                finding
                            )
                        ),
                        self.styles["small"],
                    )
                )

        return story

    # ==========================================================
    # IDS
    # ==========================================================

    def _ids_section(
        self,
        data: dict[str, Any],
    ) -> list[Any]:

        alerts = self._sequence(
            data.get("ids_alerts")
        )

        story = [
            Paragraph(
                "9. IDS / Security Detection",
                self.styles["section"],
            )
        ]

        if not alerts:
            story.append(
                Paragraph(
                    "No IDS alerts were recorded.",
                    self.styles["body"],
                )
            )
            return story

        rows = [
            [
                self._paragraph(
                    "Severity",
                    "table_header",
                ),
                self._paragraph(
                    "Type",
                    "table_header",
                ),
                self._paragraph(
                    "Source",
                    "table_header",
                ),
                self._paragraph(
                    "Description",
                    "table_header",
                ),
            ]
        ]

        for alert in alerts:
            item = self._mapping(alert)

            rows.append(
                [
                    self._paragraph(
                        self._text(
                            item.get(
                                "severity",
                                "INFO",
                            )
                        ),
                        "table_body",
                    ),
                    self._paragraph(
                        self._text(
                            item.get(
                                "type",
                                item.get(
                                    "detection_type",
                                    "Unknown",
                                ),
                            )
                        ),
                        "table_body",
                    ),
                    self._paragraph(
                        self._text(
                            item.get(
                                "source",
                                "Unknown",
                            )
                        ),
                        "table_body",
                    ),
                    self._paragraph(
                        self._text(
                            item.get(
                                "description",
                                "",
                            )
                        ),
                        "table_body",
                    ),
                ]
            )

        story.append(
            self._table(
                rows,
                [
                    25 * mm,
                    35 * mm,
                    35 * mm,
                    65 * mm,
                ],
            )
        )

        return story

    # ==========================================================
    # FIREWALL
    # ==========================================================

    def _firewall_section(
        self,
        data: dict[str, Any],
    ) -> list[Any]:

        findings = self._sequence(
            data.get("firewall_findings")
        )

        story = [
            Paragraph(
                "10. Firewall Analysis",
                self.styles["section"],
            )
        ]

        if not findings:
            story.append(
                Paragraph(
                    "No firewall findings were recorded.",
                    self.styles["body"],
                )
            )
            return story

        rows = [
            [
                self._paragraph(
                    "ID",
                    "table_header",
                ),
                self._paragraph(
                    "Severity",
                    "table_header",
                ),
                self._paragraph(
                    "Title",
                    "table_header",
                ),
                self._paragraph(
                    "Recommendation",
                    "table_header",
                ),
            ]
        ]

        for finding in findings:
            item = self._mapping(finding)

            rows.append(
                [
                    self._paragraph(
                        self._text(
                            item.get(
                                "finding_id",
                                item.get(
                                    "id",
                                    "",
                                ),
                            )
                        ),
                        "table_body",
                    ),
                    self._paragraph(
                        self._text(
                            item.get(
                                "severity",
                                "INFO",
                            )
                        ),
                        "table_body",
                    ),
                    self._paragraph(
                        self._text(
                            item.get(
                                "title",
                                item.get(
                                    "description",
                                    "",
                                ),
                            )
                        ),
                        "table_body",
                    ),
                    self._paragraph(
                        self._text(
                            item.get(
                                "recommendation",
                                item.get(
                                    "recommended_action",
                                    "",
                                ),
                            )
                        ),
                        "table_body",
                    ),
                ]
            )

        story.append(
            self._table(
                rows,
                [
                    20 * mm,
                    25 * mm,
                    55 * mm,
                    60 * mm,
                ],
            )
        )

        return story

    # ==========================================================
    # TOPOLOGY
    # ==========================================================

    def _topology_section(
        self,
        data: dict[str, Any],
    ) -> list[Any]:

        topology = self._mapping(
            data.get("topology_information")
        )

        story = [
            Paragraph(
                "11. Network Topology",
                self.styles["section"],
            )
        ]

        if not topology:
            story.append(
                Paragraph(
                    "No topology information was recorded.",
                    self.styles["body"],
                )
            )
            return story

        story.append(
            self._key_value_table(
                [
                    (
                        "Topology Available",
                        topology.get(
                            "available",
                            False,
                        ),
                    ),
                    (
                        "Nodes",
                        topology.get(
                            "nodes",
                            0,
                        ),
                    ),
                    (
                        "Connections",
                        topology.get(
                            "connections",
                            0,
                        ),
                    ),
                ]
            )
        )

        image_path = topology.get(
            "image_path"
        )

        if image_path:
            story.append(
                Paragraph(
                    "Topology image path: "
                    + self._escape(
                        self._text(image_path)
                    ),
                    self.styles["small"],
                )
            )

        story.append(
            Paragraph(
                "The topology section records the network "
                "representation available to NETWATCH at "
                "assessment time. A router identified by "
                "discovery may represent a router candidate "
                "rather than a proven default gateway.",
                self.styles["note"],
            )
        )

        return story

    # ==========================================================
    # FINDINGS
    # ==========================================================

    def _findings_section(
        self,
        data: dict[str, Any],
    ) -> list[Any]:

        story = [
            Paragraph(
                "12. Findings",
                self.styles["section"],
            )
        ]

        collections = [
            (
                "DNS",
                data.get("dns_findings"),
            ),
            (
                "HTTP/HTTPS",
                data.get("http_findings"),
            ),
            (
                "Traffic",
                data.get("traffic_findings"),
            ),
            (
                "IDS",
                data.get("ids_alerts"),
            ),
            (
                "Firewall",
                data.get("firewall_findings"),
            ),
        ]

        found_any = False

        for category, values in collections:
            items = self._sequence(values)

            for item in items:
                found_any = True

                mapping = self._mapping(item)

                severity = self._text(
                    mapping.get(
                        "severity",
                        "INFO",
                    )
                )

                title = mapping.get(
                    "title",
                    mapping.get(
                        "type",
                        mapping.get(
                            "detection_type",
                            category,
                        ),
                    ),
                )

                description = mapping.get(
                    "description",
                    mapping.get(
                        "evidence",
                        self._format_item(item),
                    ),
                )

                story.append(
                    Paragraph(
                        (
                            "<b>["
                            + self._escape(severity)
                            + "] "
                            + self._escape(
                                self._text(title)
                            )
                            + "</b><br/>"
                            + self._escape(
                                self._text(description)
                            )
                        ),
                        self.styles["small"],
                    )
                )

        if not found_any:
            story.append(
                Paragraph(
                    "No findings were recorded.",
                    self.styles["body"],
                )
            )

        story.append(
            Paragraph(
                "Findings represent observations from the "
                "available assessment data and should be "
                "validated by an authorized network "
                "administrator or security professional.",
                self.styles["note"],
            )
        )

        return story

    # ==========================================================
    # SEVERITY
    # ==========================================================

    def _severity_section(
        self,
        data: dict[str, Any],
    ) -> list[Any]:

        summary = self._mapping(
            data.get("finding_summary")
        )

        rows = [
            [
                self._paragraph(
                    "Severity",
                    "table_header",
                ),
                self._paragraph(
                    "Count",
                    "table_header",
                ),
            ]
        ]

        for severity in SEVERITIES:
            value = summary.get(
                severity.lower(),
                summary.get(
                    severity,
                    0,
                ),
            )

            rows.append(
                [
                    self._paragraph(
                        severity,
                        "table_body",
                    ),
                    self._paragraph(
                        str(value),
                        "table_body",
                    ),
                ]
            )

        total = summary.get(
            "total",
            self._calculate_total(summary),
        )

        rows.append(
            [
                self._paragraph(
                    "TOTAL",
                    "table_header",
                ),
                self._paragraph(
                    str(total),
                    "table_header",
                ),
            ]
        )

        return [
            Paragraph(
                "13. Risk / Severity Summary",
                self.styles["section"],
            ),

            self._table(
                rows,
                [90 * mm, 40 * mm],
            ),

            Paragraph(
                "Severity is presented as a classification "
                "of observed findings. It is not a statement "
                "of malicious intent.",
                self.styles["note"],
            ),
        ]

    # ==========================================================
    # RECOMMENDATIONS
    # ==========================================================

    def _recommendations_section(
        self,
        data: dict[str, Any],
    ) -> list[Any]:

        recommendations = self._sequence(
            data.get("recommendations")
        )

        story = [
            Paragraph(
                "14. Recommendations",
                self.styles["section"],
            )
        ]

        if not recommendations:
            story.append(
                Paragraph(
                    "No specific recommendations were recorded.",
                    self.styles["body"],
                )
            )
            return story

        for index, recommendation in enumerate(
            recommendations,
            start=1,
        ):
            recommendation_text = self._text(
                recommendation
            )

            story.append(
                Paragraph(
                    "<b>"
                    + str(index)
                    + ".</b> "
                    + self._escape(
                        recommendation_text
                    ),
                    self.styles["body"],
                )
            )

        return story

    # ==========================================================
    # NOTES
    # ==========================================================

    def _notes_section(
        self,
        data: dict[str, Any],
    ) -> list[Any]:

        notes = self._sequence(
            data.get("notes")
        )

        story = [
            Paragraph(
                "15. Assessment Notes",
                self.styles["section"],
            )
        ]

        if not notes:
            story.append(
                Paragraph(
                    "No additional assessment notes were recorded.",
                    self.styles["body"],
                )
            )
            return story

        for note in notes:
            story.append(
                Paragraph(
                    self._escape(
                        self._text(note)
                    ),
                    self.styles["body"],
                )
            )

        return story

    # ==========================================================
    # TECHNICAL APPENDIX
    # ==========================================================

    def _technical_appendix(
        self,
        data: dict[str, Any],
    ) -> list[Any]:

        return [
            PageBreak(),

            Paragraph(
                "16. Technical Appendix",
                self.styles["section"],
            ),

            Paragraph(
                "The following assessment components were "
                "available to the report generator:",
                self.styles["body"],
            ),

            self._key_value_table(
                [
                    (
                        "Devices",
                        len(
                            self._sequence(
                                data.get(
                                    "discovered_devices"
                                )
                            )
                        ),
                    ),
                    (
                        "Open Ports",
                        len(
                            self._sequence(
                                data.get(
                                    "open_ports"
                                )
                            )
                        ),
                    ),
                    (
                        "Services",
                        len(
                            self._sequence(
                                data.get(
                                    "detected_services"
                                )
                            )
                        ),
                    ),
                    (
                        "DNS Observations",
                        len(
                            self._sequence(
                                data.get(
                                    "dns_findings"
                                )
                            )
                        ),
                    ),
                    (
                        "HTTP Observations",
                        len(
                            self._sequence(
                                data.get(
                                    "http_findings"
                                )
                            )
                        ),
                    ),
                    (
                        "Traffic Observations",
                        len(
                            self._sequence(
                                data.get(
                                    "traffic_findings"
                                )
                            )
                        ),
                    ),
                    (
                        "IDS Alerts",
                        len(
                            self._sequence(
                                data.get(
                                    "ids_alerts"
                                )
                            )
                        ),
                    ),
                    (
                        "Firewall Findings",
                        len(
                            self._sequence(
                                data.get(
                                    "firewall_findings"
                                )
                            )
                        ),
                    ),
                ]
            ),

            Spacer(1, 5 * mm),

            Paragraph(
                "Report generation timestamp: "
                + self._escape(
                    datetime.now(UTC)
                    .replace(microsecond=0)
                    .isoformat()
                    .replace(
                        "+00:00",
                        "Z",
                    )
                ),
                self.styles["small"],
            ),

            Paragraph(
                "NETWATCH is designed for authorized "
                "defensive network assessment and monitoring.",
                self.styles["note"],
            ),
        ]

    # ==========================================================
    # TABLE HELPERS
    # ==========================================================

    def _table(
        self,
        rows: list[list[Any]],
        widths: list[float],
    ) -> Table:

        table = Table(
            rows,
            colWidths=widths,
            repeatRows=1,
            hAlign="LEFT",
        )

        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#E8E8E8"),
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.black,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.HexColor("#AAAAAA"),
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                ]
            )
        )

        return table

    def _key_value_table(
        self,
        pairs: Sequence[tuple[str, Any]],
    ) -> Table:

        rows = []

        for key, value in pairs:
            rows.append(
                [
                    self._paragraph(
                        self._text(key),
                        "table_header",
                    ),
                    self._paragraph(
                        self._text(value),
                        "table_body",
                    ),
                ]
            )

        return self._table(
            rows,
            [
                70 * mm,
                90 * mm,
            ],
        )

    # ==========================================================
    # GENERAL HELPERS
    # ==========================================================

    @staticmethod
    def _mapping(
        value: Any,
    ) -> dict[str, Any]:

        if value is None:
            return {}

        if isinstance(value, Mapping):
            return dict(value)

        if is_dataclass(value):
            return asdict(value)

        if hasattr(value, "to_dict"):
            result = value.to_dict()

            if isinstance(
                result,
                Mapping,
            ):
                return dict(result)

        if hasattr(value, "__dict__"):
            return dict(vars(value))

        return {}

    @staticmethod
    def _sequence(
        value: Any,
    ) -> list[Any]:

        if value is None:
            return []

        if isinstance(
            value,
            (list, tuple),
        ):
            return list(value)

        if isinstance(
            value,
            set,
        ):
            return list(value)

        return []

    @staticmethod
    def _text(
        value: Any,
    ) -> str:

        if value is None:
            return ""

        return str(value)

    def _paragraph(
        self,
        text: str,
        style_name: str,
    ) -> Paragraph:

        return Paragraph(
            self._escape(text),
            self.styles[style_name],
        )

    @staticmethod
    def _escape(
        value: str,
    ) -> str:

        text = str(value)

        return (
            text.replace(
                "&",
                "&amp;",
            )
            .replace(
                "<",
                "&lt;",
            )
            .replace(
                ">",
                "&gt;",
            )
        )

    @staticmethod
    def _safe_filename_part(
        value: str,
    ) -> str:

        allowed = (
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789-_"
        )

        cleaned = "".join(
            character
            if character in allowed
            else "_"
            for character in str(value)
        )

        return (
            cleaned.strip("_")
            or "assessment"
        )

    @staticmethod
    def _calculate_total(
        summary: Mapping[str, Any],
    ) -> int:

        total = 0

        for severity in SEVERITIES:
            total += int(
                summary.get(
                    severity.lower(),
                    summary.get(
                        severity,
                        0,
                    ),
                )
                or 0
            )

        return total

    @staticmethod
    def _format_mapping(
        item: Mapping[str, Any],
    ) -> str:

        return " | ".join(
            f"{key}: {value}"
            for key, value in item.items()
        )

    def _format_item(
        self,
        item: Any,
    ) -> str:

        mapping = self._mapping(item)

        if mapping:
            return self._format_mapping(
                mapping
            )

        return self._text(item)

    @staticmethod
    def _draw_footer(
        canvas,
        document,
    ) -> None:

        canvas.saveState()

        width, _ = A4

        canvas.setFont(
            "Helvetica",
            7,
        )

        canvas.drawString(
            15 * mm,
            8 * mm,
            "NETWATCH — Authorized Security Assessment",
        )

        canvas.drawRightString(
            width - 15 * mm,
            8 * mm,
            f"Page {document.page}",
        )

        canvas.restoreState()


def format_report_information(
    report_path: str | Path,
) -> str:
    """Return human-readable information about a generated report."""

    path = Path(report_path)

    if not path.exists():
        return (
            "Report file does not exist: "
            f"{path}"
        )

    size = path.stat().st_size

    return (
        "PDF REPORT\n"
        "-----------\n"
        f"Path : {path}\n"
        f"Size : {size} bytes\n"
        "Exists: Yes"
    )