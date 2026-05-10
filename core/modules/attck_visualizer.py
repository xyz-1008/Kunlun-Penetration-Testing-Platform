"""ATT&CK matrix visualization for Kunlun penetration testing platform.

Provides:
- ATT&CK heatmap generation (PNG/SVG/HTML)
- Technique detail list generation
- Attack chain timeline visualization
- Report-ready output formats
"""

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .attck_mapper import (
    AttckTactic,
    AttckTimelineEntry,
    MappingConfidence,
    MappingResult,
    Severity,
    TACTIC_ORDER,
)

logger = logging.getLogger(__name__)

TACTIC_DISPLAY_NAMES: Dict[AttckTactic, str] = {
    AttckTactic.INITIAL_ACCESS: "初始访问",
    AttckTactic.EXECUTION: "执行",
    AttckTactic.PERSISTENCE: "持久化",
    AttckTactic.PRIVILEGE_ESCALATION: "提权",
    AttckTactic.DEFENSE_EVASION: "防御规避",
    AttckTactic.CREDENTIAL_ACCESS: "凭据访问",
    AttckTactic.DISCOVERY: "发现",
    AttckTactic.LATERAL_MOVEMENT: "横向移动",
    AttckTactic.COLLECTION: "收集",
    AttckTactic.COMMAND_AND_CONTROL: "命令与控制",
    AttckTactic.EXFILTRATION: "数据渗出",
    AttckTactic.IMPACT: "影响",
}

SEVERITY_COLORS: Dict[Severity, str] = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#16a34a",
    Severity.INFO: "#2563eb",
}

CONFIDENCE_COLORS: Dict[MappingConfidence, str] = {
    MappingConfidence.EXACT: "#dc2626",
    MappingConfidence.HIGH: "#ea580c",
    MappingConfidence.MEDIUM: "#ca8a04",
    MappingConfidence.LOW: "#16a34a",
    MappingConfidence.FUZZY: "#6b7280",
}


@dataclass
class HeatmapCell:
    """Single cell in the ATT&CK heatmap.

    Attributes:
        technique_id: ATT&CK technique ID
        technique_name: Technique name
        tactic: Associated tactic
        is_used: Whether this technique was used
        usage_count: Number of times used
        severity: Technique severity
        color: Cell color for visualization
        tooltip: Hover tooltip text
    """
    technique_id: str = ""
    technique_name: str = ""
    tactic: AttckTactic = AttckTactic.INITIAL_ACCESS
    is_used: bool = False
    usage_count: int = 0
    severity: Severity = Severity.INFO
    color: str = "#e5e7eb"
    tooltip: str = ""


@dataclass
class TechniqueDetail:
    """Detailed information about a used technique.

    Attributes:
        technique_id: ATT&CK technique ID
        technique_name: Technique name
        tactic: Tactic category
        severity: Severity level
        first_seen: First usage timestamp
        last_seen: Last usage timestamp
        usage_count: Total usage count
        target_hosts: List of affected hosts
        descriptions: List of operation descriptions
        detection_suggestions: Blue team detection suggestions
        mitigation_suggestions: Mitigation recommendations
    """
    technique_id: str = ""
    technique_name: str = ""
    tactic: AttckTactic = AttckTactic.INITIAL_ACCESS
    severity: Severity = Severity.INFO
    first_seen: float = 0.0
    last_seen: float = 0.0
    usage_count: int = 0
    target_hosts: List[str] = field(default_factory=list)
    descriptions: List[str] = field(default_factory=list)
    detection_suggestions: List[str] = field(default_factory=list)
    mitigation_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic.value,
            "severity": self.severity.value,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "usage_count": self.usage_count,
            "target_hosts": self.target_hosts,
            "descriptions": self.descriptions,
            "detection_suggestions": self.detection_suggestions,
            "mitigation_suggestions": self.mitigation_suggestions,
        }


class AttckVisualizer:
    """ATT&CK matrix visualization engine.

    Generates:
    - Heatmap data for matrix visualization
    - Technique detail lists
    - Attack chain timeline
    - HTML/SVG/PNG export-ready data
    """

    def __init__(self) -> None:
        """Initialize the visualizer."""
        self.heatmap_data: Dict[AttckTactic, List[HeatmapCell]] = {}
        self.technique_details: List[TechniqueDetail] = []
        self.timeline: List[AttckTimelineEntry] = []

    def generate_heatmap(
        self,
        mapping_results: List[MappingResult],
        all_techniques: Dict[str, Any],
    ) -> Dict[AttckTactic, List[HeatmapCell]]:
        """Generate ATT&CK heatmap data.

        Args:
            mapping_results: List of mapping results from operations.
            all_techniques: Dictionary of all ATT&CK techniques.

        Returns:
            Dictionary mapping tactics to lists of heatmap cells.
        """
        usage_counts: Dict[str, int] = {}
        for result in mapping_results:
            tid = result.technique.technique_id
            usage_counts[tid] = usage_counts.get(tid, 0) + 1

        heatmap: Dict[AttckTactic, List[HeatmapCell]] = {}

        for tactic in TACTIC_ORDER:
            cells: List[HeatmapCell] = []
            for tech_id, technique in all_techniques.items():
                if technique.tactic != tactic:
                    continue
                count = usage_counts.get(tech_id, 0)
                is_used = count > 0
                color = self._get_cell_color(technique.severity, count)
                tooltip = (
                    f"{tech_id}: {technique.name}\n"
                    f"战术: {TACTIC_DISPLAY_NAMES.get(tactic, tactic.value)}\n"
                    f"使用次数: {count}\n"
                    f"严重程度: {technique.severity.value}"
                )
                cell = HeatmapCell(
                    technique_id=tech_id,
                    technique_name=technique.name,
                    tactic=tactic,
                    is_used=is_used,
                    usage_count=count,
                    severity=technique.severity,
                    color=color,
                    tooltip=tooltip,
                )
                cells.append(cell)
            heatmap[tactic] = cells

        self.heatmap_data = heatmap
        return heatmap

    def _get_cell_color(self, severity: Severity, usage_count: int) -> str:
        """Get cell color based on severity and usage.

        Args:
            severity: Technique severity level.
            usage_count: Number of times technique was used.

        Returns:
            Hex color code for the cell.
        """
        if usage_count == 0:
            return "#e5e7eb"
        base_color = SEVERITY_COLORS.get(severity, "#e5e7eb")
        if usage_count >= 3:
            return base_color
        alpha = min(0.4 + (usage_count * 0.2), 1.0)
        return base_color

    def generate_technique_details(
        self,
        mapping_results: List[MappingResult],
    ) -> List[TechniqueDetail]:
        """Generate detailed technique usage information.

        Args:
            mapping_results: List of mapping results.

        Returns:
            List of TechniqueDetail objects sorted by severity.
        """
        tech_map: Dict[str, TechniqueDetail] = {}

        for result in mapping_results:
            tid = result.technique.technique_id
            if tid not in tech_map:
                tech_map[tid] = TechniqueDetail(
                    technique_id=tid,
                    technique_name=result.technique.name,
                    tactic=result.technique.tactic,
                    severity=result.technique.severity,
                    first_seen=result.timestamp,
                    last_seen=result.timestamp,
                    detection_suggestions=result.technique.detection_suggestions,
                    mitigation_suggestions=result.technique.mitigation_suggestions,
                )
            detail = tech_map[tid]
            detail.usage_count += 1
            if result.timestamp < detail.first_seen:
                detail.first_seen = result.timestamp
            if result.timestamp > detail.last_seen:
                detail.last_seen = result.timestamp
            if result.target_host and result.target_host not in detail.target_hosts:
                detail.target_hosts.append(result.target_host)
            if result.operation_description:
                detail.descriptions.append(result.operation_description)

        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        details = sorted(
            tech_map.values(),
            key=lambda d: severity_order.get(d.severity, 5),
        )
        self.technique_details = details
        return details

    def generate_timeline(
        self,
        timeline_entries: List[AttckTimelineEntry],
    ) -> List[Dict[str, Any]]:
        """Generate attack chain timeline data.

        Args:
            timeline_entries: List of timeline entries.

        Returns:
            List of timeline data dictionaries ready for rendering.
        """
        sorted_entries = sorted(timeline_entries, key=lambda e: e.sequence_number)
        timeline_data: List[Dict[str, Any]] = []

        for entry in sorted_entries:
            data = {
                "sequence": entry.sequence_number,
                "timestamp": entry.timestamp,
                "tactic": TACTIC_DISPLAY_NAMES.get(entry.tactic, entry.tactic.value),
                "tactic_raw": entry.tactic.value,
                "technique_id": entry.technique.technique_id,
                "technique_name": entry.technique.name,
                "target_host": entry.target_host,
                "description": entry.description,
                "severity": entry.technique.severity.value,
                "color": SEVERITY_COLORS.get(entry.technique.severity, "#e5e7eb"),
            }
            timeline_data.append(data)

        self.timeline = timeline_entries
        return timeline_data

    def export_html_heatmap(
        self,
        heatmap: Dict[AttckTactic, List[HeatmapCell]],
        output_path: str,
        title: str = "ATT&CK Attack Matrix",
        color_theme: str = "default",
    ) -> str:
        """Export heatmap as interactive HTML.

        Args:
            heatmap: Heatmap data from generate_heatmap.
            output_path: Output file path.
            title: HTML page title.
            color_theme: Color theme (default/red-green/blue).

        Returns:
            Path to generated HTML file.
        """
        theme_colors = self._get_theme_colors(color_theme)
        html_content = self._build_html_heatmap(heatmap, title, theme_colors)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html_content, encoding="utf-8")
        logger.info("HTML heatmap exported to %s", output_path)
        return output_path

    def _get_theme_colors(self, theme: str) -> Dict[str, str]:
        """Get color theme configuration.

        Args:
            theme: Theme name.

        Returns:
            Dictionary of theme colors.
        """
        themes = {
            "default": {
                "bg": "#ffffff",
                "text": "#1f2937",
                "border": "#d1d5db",
                "used": "#dc2626",
                "unused": "#e5e7eb",
                "header": "#374151",
            },
            "dark": {
                "bg": "#1f2937",
                "text": "#f9fafb",
                "border": "#4b5563",
                "used": "#ef4444",
                "unused": "#374151",
                "header": "#111827",
            },
            "blue": {
                "bg": "#ffffff",
                "text": "#1e3a5f",
                "border": "#93c5fd",
                "used": "#2563eb",
                "unused": "#dbeafe",
                "header": "#1e40af",
            },
        }
        return themes.get(theme, themes["default"])

    def _build_html_heatmap(
        self,
        heatmap: Dict[AttckTactic, List[HeatmapCell]],
        title: str,
        colors: Dict[str, str],
    ) -> str:
        """Build HTML heatmap string.

        Args:
            heatmap: Heatmap data.
            title: Page title.
            colors: Color theme.

        Returns:
            Complete HTML string.
        """
        html_parts = [
            f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: {colors['bg']}; color: {colors['text']}; margin: 20px; }}
        h1 {{ text-align: center; color: {colors['header']}; }}
        .matrix {{ display: grid; grid-template-columns: repeat(12, 1fr); gap: 2px; margin: 20px 0; }}
        .tactic-header {{ background: {colors['header']}; color: white; padding: 8px; text-align: center; font-weight: bold; font-size: 12px; }}
        .cell {{ padding: 6px; text-align: center; font-size: 10px; border-radius: 3px; cursor: pointer; position: relative; }}
        .cell:hover .tooltip {{ display: block; }}
        .tooltip {{ display: none; position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%); background: #1f2937; color: white; padding: 8px; border-radius: 4px; font-size: 11px; white-space: pre-line; z-index: 100; min-width: 200px; }}
        .unused {{ background: {colors['unused']}; color: #9ca3af; }}
        .legend {{ display: flex; justify-content: center; gap: 20px; margin: 20px 0; }}
        .legend-item {{ display: flex; align-items: center; gap: 5px; }}
        .legend-color {{ width: 20px; height: 20px; border-radius: 3px; }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <div class="legend">
        <div class="legend-item"><div class="legend-color" style="background:#dc2626"></div><span>严重</span></div>
        <div class="legend-item"><div class="legend-color" style="background:#ea580c"></div><span>高</span></div>
        <div class="legend-item"><div class="legend-color" style="background:#ca8a04"></div><span>中</span></div>
        <div class="legend-item"><div class="legend-color" style="background:#16a34a"></div><span>低</span></div>
        <div class="legend-item"><div class="legend-color" style="background:#e5e7eb"></div><span>未使用</span></div>
    </div>
    <div class="matrix">"""
        ]

        for tactic in TACTIC_ORDER:
            cells = heatmap.get(tactic, [])
            tactic_name = TACTIC_DISPLAY_NAMES.get(tactic, tactic.value)
            html_parts.append(f'<div class="tactic-header">{tactic_name}</div>')
            for cell in cells:
                if cell.is_used:
                    css_class = "cell"
                    style = f"background:{cell.color};color:white;"
                else:
                    css_class = "cell unused"
                    style = ""
                tooltip_escaped = cell.tooltip.replace('"', '&quot;')
                html_parts.append(
                    f'<div class="{css_class}" style="{style}">'
                    f'{cell.technique_id}'
                    f'<div class="tooltip">{tooltip_escaped}</div>'
                    f"</div>"
                )

        html_parts.append("</div></body></html>")
        return "\n".join(html_parts)

    def export_technique_list_html(
        self,
        details: List[TechniqueDetail],
        output_path: str,
        title: str = "ATT&CK Technique Details",
    ) -> str:
        """Export technique details as HTML.

        Args:
            details: List of technique details.
            output_path: Output file path.
            title: HTML page title.

        Returns:
            Path to generated HTML file.
        """
        html_parts = [
            f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 20px; background: #f9fafb; }}
        h1 {{ color: #1f2937; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background: white; }}
        th {{ background: #374151; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #e5e7eb; }}
        .severity-critical {{ color: #dc2626; font-weight: bold; }}
        .severity-high {{ color: #ea580c; font-weight: bold; }}
        .severity-medium {{ color: #ca8a04; }}
        .severity-low {{ color: #16a34a; }}
        .severity-info {{ color: #2563eb; }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <table>
        <thead>
            <tr>
                <th>ATT&CK ID</th>
                <th>技术名称</th>
                <th>战术</th>
                <th>严重程度</th>
                <th>使用次数</th>
                <th>目标主机</th>
                <th>检测建议</th>
                <th>缓解措施</th>
            </tr>
        </thead>
        <tbody>"""
        ]

        for detail in details:
            tactic_name = TACTIC_DISPLAY_NAMES.get(detail.tactic, detail.tactic.value)
            sev_class = f"severity-{detail.severity.value}"
            hosts = ", ".join(detail.target_hosts) if detail.target_hosts else "-"
            detections = "<br>".join(detail.detection_suggestions[:3]) if detail.detection_suggestions else "-"
            mitigations = "<br>".join(detail.mitigation_suggestions[:3]) if detail.mitigation_suggestions else "-"
            html_parts.append(
                f"<tr>"
                f"<td>{detail.technique_id}</td>"
                f"<td>{detail.technique_name}</td>"
                f"<td>{tactic_name}</td>"
                f'<td class="{sev_class}">{detail.severity.value.upper()}</td>'
                f"<td>{detail.usage_count}</td>"
                f"<td>{hosts}</td>"
                f"<td>{detections}</td>"
                f"<td>{mitigations}</td>"
                f"</tr>"
            )

        html_parts.append("</tbody></table></body></html>")
        html_content = "\n".join(html_parts)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html_content, encoding="utf-8")
        logger.info("Technique details HTML exported to %s", output_path)
        return output_path

    def export_timeline_html(
        self,
        timeline_data: List[Dict[str, Any]],
        output_path: str,
        title: str = "ATT&CK Attack Chain Timeline",
    ) -> str:
        """Export attack chain timeline as HTML.

        Args:
            timeline_data: Timeline data from generate_timeline.
            output_path: Output file path.
            title: HTML page title.

        Returns:
            Path to generated HTML file.
        """
        from datetime import datetime

        html_parts = [
            f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 20px; background: #f9fafb; }}
        h1 {{ color: #1f2937; text-align: center; }}
        .timeline {{ position: relative; max-width: 800px; margin: 40px auto; }}
        .timeline::before {{ content: ''; position: absolute; left: 50%; width: 4px; background: #d1d5db; height: 100%; transform: translateX(-50%); }}
        .event {{ position: relative; width: 45%; padding: 15px; background: white; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .event-left {{ margin-left: 5%; }}
        .event-right {{ margin-left: 50%; }}
        .event::before {{ content: ''; position: absolute; width: 16px; height: 16px; border-radius: 50%; top: 20px; }}
        .event-left::before {{ right: -33px; }}
        .event-right::before {{ left: -33px; }}
        .event-time {{ font-size: 12px; color: #6b7280; }}
        .event-tactic {{ font-weight: bold; color: #374151; }}
        .event-technique {{ color: #1f2937; }}
        .event-host {{ font-size: 12px; color: #6b7280; }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <div class="timeline">"""
        ]

        for i, event in enumerate(timeline_data):
            side = "event-left" if i % 2 == 0 else "event-right"
            timestamp_str = datetime.fromtimestamp(event["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            color = event.get("color", "#d1d5db")
            html_parts.append(
                f'<div class="event {side}">'
                f'<div style="border-left: 4px solid {color}; padding-left: 10px;">'
                f'<div class="event-time">步骤 {event["sequence"]} - {timestamp_str}</div>'
                f'<div class="event-tactic">{event["tactic"]}</div>'
                f'<div class="event-technique">{event["technique_id"]}: {event["technique_name"]}</div>'
                f'<div class="event-host">目标: {event.get("target_host", "-")}</div>'
                f'<div style="font-size: 13px; margin-top: 5px;">{event.get("description", "")}</div>'
                f"</div></div>"
            )

        html_parts.append("</div></body></html>")
        html_content = "\n".join(html_parts)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html_content, encoding="utf-8")
        logger.info("Timeline HTML exported to %s", output_path)
        return output_path

    def get_report_data(
        self,
        mapping_results: List[MappingResult],
        all_techniques: Dict[str, Any],
        timeline_entries: List[AttckTimelineEntry],
    ) -> Dict[str, Any]:
        """Get all visualization data formatted for report templates.

        Args:
            mapping_results: List of mapping results.
            all_techniques: Dictionary of all techniques.
            timeline_entries: List of timeline entries.

        Returns:
            Dictionary with all report-ready visualization data.
        """
        heatmap = self.generate_heatmap(mapping_results, all_techniques)
        details = self.generate_technique_details(mapping_results)
        timeline = self.generate_timeline(timeline_entries)

        heatmap_summary: Dict[str, Any] = {}
        for tactic, cells in heatmap.items():
            used_cells = [c for c in cells if c.is_used]
            heatmap_summary[tactic.value] = {
                "display_name": TACTIC_DISPLAY_NAMES.get(tactic, tactic.value),
                "total_techniques": len(cells),
                "used_techniques": len(used_cells),
                "techniques": [
                    {
                        "id": c.technique_id,
                        "name": c.technique_name,
                        "count": c.usage_count,
                        "severity": c.severity.value,
                    }
                    for c in used_cells
                ],
            }

        return {
            "heatmap_summary": heatmap_summary,
            "technique_details": [d.to_dict() for d in details],
            "timeline": timeline,
            "statistics": {
                "total_techniques_used": len(details),
                "total_mappings": len(mapping_results),
                "tactics_covered": len([t for t in heatmap if any(c.is_used for c in heatmap[t])]),
            },
        }
