"""Mobile IoT Integration: Integration layer with asset recognition, PoC engine, and report modules.

Provides:
- Automatic asset registration for mobile/IoT discoveries
- PoC engine triggering for detected devices/versions
- Report module integration for mobile/IoT security assessment chapters
- Event bus integration for real-time notifications
- Unified data models for cross-module communication
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

from .mobile_apk_parser import APKAnalysisResult, APKParser, SecurityFinding as APKSecurityFinding
from .mobile_ipa_parser import IPAAnalysisResult, IPAParser, SecurityFinding as IPASecurityFinding
from .mobile_sensitive_detector import DetectionResult, SensitiveDetector, DetectedSecret
from .iot_mqtt_scanner import MQTTScanResult, MQTTScanner
from .iot_coap_scanner import CoAPScanResult, CoAPScanner
from .iot_modbus_scanner import ModbusScanResult, ModbusScanner
from .wireless_ble_scanner import BLEScanResult, BLEScanner, BLEDeviceInfo

logger = logging.getLogger(__name__)


class AssetType(Enum):
    """Types of discovered assets."""
    ANDROID_APP = "android_app"
    IOS_APP = "ios_app"
    MQTT_BROKER = "mqtt_broker"
    COAP_DEVICE = "coap_device"
    MODBUS_DEVICE = "modbus_device"
    BLE_DEVICE = "ble_device"
    IOT_GATEWAY = "iot_gateway"


class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DiscoveredAsset:
    """Discovered mobile/IoT asset.

    Attributes:
        asset_id: Unique asset identifier
        asset_type: Type of asset
        name: Asset name/identifier
        host: Host address (if applicable)
        port: Port number (if applicable)
        metadata: Additional metadata
        discovery_timestamp: Discovery timestamp
        security_findings: Associated security findings
    """
    asset_id: str = ""
    asset_type: AssetType = AssetType.ANDROID_APP
    name: str = ""
    host: str = ""
    port: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovery_timestamp: float = 0.0
    security_findings: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class MobileIoTReport:
    """Mobile and IoT security assessment report.

    Attributes:
        report_id: Unique report identifier
        title: Report title
        summary: Executive summary
        mobile_findings: Mobile application findings
        iot_findings: IoT device findings
        wireless_findings: Wireless device findings
        recommendations: Security recommendations
        generated_timestamp: Report generation timestamp
    """
    report_id: str = ""
    title: str = ""
    summary: str = ""
    mobile_findings: List[Dict[str, Any]] = field(default_factory=list)
    iot_findings: List[Dict[str, Any]] = field(default_factory=list)
    wireless_findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    generated_timestamp: float = 0.0


class MobileIoTIntegration:
    """Integration layer for mobile and IoT testing components.

    Connects APK/IPA analysis, IoT protocol scanning, and wireless
    discovery with the asset recognition, PoC engine, and report modules.
    """

    def __init__(
        self,
        asset_registry_callback: Optional[Callable[[DiscoveredAsset], Coroutine[Any, Any, None]]] = None,
        poc_trigger_callback: Optional[Callable[[str, Dict[str, Any]], Coroutine[Any, Any, None]]] = None,
        report_callback: Optional[Callable[[MobileIoTReport], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Initialize integration layer.

        Args:
            asset_registry_callback: Callback to register discovered assets.
            poc_trigger_callback: Callback to trigger PoC execution.
            report_callback: Callback to submit reports.
        """
        self.apk_parser = APKParser()
        self.ipa_parser = IPAParser()
        self.sensitive_detector = SensitiveDetector()
        self.mqtt_scanner = MQTTScanner()
        self.coap_scanner = CoAPScanner()
        self.modbus_scanner = ModbusScanner()
        self.ble_scanner = BLEScanner()

        self._asset_registry_callback = asset_registry_callback
        self._poc_trigger_callback = poc_trigger_callback
        self._report_callback = report_callback

        self._discovered_assets: List[DiscoveredAsset] = []
        self._asset_counter = 0

    async def analyze_apk(
        self,
        apk_path: str,
        register_asset: bool = True,
        trigger_poc: bool = True,
    ) -> APKAnalysisResult:
        """Analyze an Android APK file and integrate with platform.

        Args:
            apk_path: Path to APK file.
            register_asset: Whether to register discovered assets.
            trigger_poc: Whether to trigger relevant PoCs.

        Returns:
            APKAnalysisResult with analysis data.
        """
        result = await self.apk_parser.parse_apk(apk_path)

        if register_asset:
            asset = self._create_asset_from_apk(result)
            await self._register_asset(asset)

        if trigger_poc:
            await self._trigger_apk_pocs(result)

        sensitive_result = await self.sensitive_detector.detect_from_apk(apk_path)
        self._add_sensitive_findings(result, sensitive_result)

        return result

    async def analyze_ipa(
        self,
        ipa_path: str,
        register_asset: bool = True,
        trigger_poc: bool = True,
    ) -> IPAAnalysisResult:
        """Analyze an iOS IPA file and integrate with platform.

        Args:
            ipa_path: Path to IPA file.
            register_asset: Whether to register discovered assets.
            trigger_poc: Whether to trigger relevant PoCs.

        Returns:
            IPAAnalysisResult with analysis data.
        """
        result = await self.ipa_parser.parse_ipa(ipa_path)

        if register_asset:
            asset = self._create_asset_from_ipa(result)
            await self._register_asset(asset)

        if trigger_poc:
            await self._trigger_ipa_pocs(result)

        sensitive_result = await self.sensitive_detector.detect_from_ipa(ipa_path)
        self._add_sensitive_findings_to_ipa(result, sensitive_result)

        return result

    async def scan_mqtt(
        self,
        host: str,
        port: int = 1883,
        use_tls: bool = False,
        register_asset: bool = True,
    ) -> MQTTScanResult:
        """Scan an MQTT broker and integrate with platform.

        Args:
            host: Broker host address.
            port: Broker port number.
            use_tls: Whether to use TLS.
            register_asset: Whether to register discovered assets.

        Returns:
            MQTTScanResult with scan data.
        """
        result = await self.mqtt_scanner.scan_broker(host, port, use_tls)

        if register_asset:
            asset = self._create_asset_from_mqtt(result, host, port)
            await self._register_asset(asset)

        return result

    async def scan_coap(
        self,
        host: str,
        port: int = 5683,
        register_asset: bool = True,
    ) -> CoAPScanResult:
        """Scan a CoAP device and integrate with platform.

        Args:
            host: Device host address.
            port: Device port number.
            register_asset: Whether to register discovered assets.

        Returns:
            CoAPScanResult with scan data.
        """
        result = await self.coap_scanner.scan_device(host, port)

        if register_asset and result.device_info:
            asset = self._create_asset_from_coap(result, host, port)
            await self._register_asset(asset)

        return result

    async def scan_modbus(
        self,
        host: str,
        port: int = 502,
        unit_id: int = 1,
        register_asset: bool = True,
    ) -> ModbusScanResult:
        """Scan a Modbus device and integrate with platform.

        Args:
            host: Device host address.
            port: Device port number.
            unit_id: Unit identifier.
            register_asset: Whether to register discovered assets.

        Returns:
            ModbusScanResult with scan data.
        """
        result = await self.modbus_scanner.scan_device(host, port, unit_id)

        if register_asset and result.device_info:
            asset = self._create_asset_from_modbus(result, host, port, unit_id)
            await self._register_asset(asset)

        return result

    async def scan_ble(
        self,
        duration: float = 10.0,
        register_asset: bool = True,
    ) -> BLEScanResult:
        """Scan for BLE devices and integrate with platform.

        Args:
            duration: Scan duration in seconds.
            register_asset: Whether to register discovered assets.

        Returns:
            BLEScanResult with scan data.
        """
        result = await self.ble_scanner.scan_devices(duration)

        if register_asset:
            for device in result.discovered_devices:
                asset = self._create_asset_from_ble(device)
                await self._register_asset(asset)

        return result

    async def generate_report(
        self,
        title: str = "Mobile and IoT Security Assessment",
    ) -> MobileIoTReport:
        """Generate a comprehensive mobile and IoT security report.

        Args:
            title: Report title.

        Returns:
            MobileIoTReport with all findings.
        """
        report = MobileIoTReport(
            report_id=f"report_{int(time.time())}",
            title=title,
            summary=self._generate_summary(),
            generated_timestamp=time.time(),
        )

        for asset in self._discovered_assets:
            if asset.asset_type in (AssetType.ANDROID_APP, AssetType.IOS_APP):
                report.mobile_findings.append(self._asset_to_report_entry(asset))
            elif asset.asset_type in (
                AssetType.MQTT_BROKER, AssetType.COAP_DEVICE,
                AssetType.MODBUS_DEVICE, AssetType.IOT_GATEWAY,
            ):
                report.iot_findings.append(self._asset_to_report_entry(asset))
            elif asset.asset_type == AssetType.BLE_DEVICE:
                report.wireless_findings.append(self._asset_to_report_entry(asset))

        report.recommendations = self._generate_recommendations()

        if self._report_callback:
            try:
                await self._report_callback(report)
            except Exception as e:
                logger.error(f"Failed to submit report: {e}")

        return report

    def _create_asset_from_apk(self, result: APKAnalysisResult) -> DiscoveredAsset:
        """Create asset from APK analysis result.

        Args:
            result: APK analysis result.

        Returns:
            DiscoveredAsset object.
        """
        self._asset_counter += 1

        findings = []
        for finding in result.security_findings:
            findings.append({
                "id": finding.finding_id,
                "risk": finding.risk_level.value,
                "title": finding.title,
                "description": finding.description,
            })

        return DiscoveredAsset(
            asset_id=f"asset_{self._asset_counter:04d}",
            asset_type=AssetType.ANDROID_APP,
            name=result.package_name or result.apk_path,
            metadata={
                "version_name": result.version_name,
                "version_code": result.version_code,
                "permissions": result.permissions,
                "exported_components": [c.name for c in result.exported_components],
                "detected_sdks": [s.sdk_name for s in result.detected_sdks],
            },
            discovery_timestamp=time.time(),
            security_findings=findings,
        )

    def _create_asset_from_ipa(self, result: IPAAnalysisResult) -> DiscoveredAsset:
        """Create asset from IPA analysis result.

        Args:
            result: IPA analysis result.

        Returns:
            DiscoveredAsset object.
        """
        self._asset_counter += 1

        findings = []
        for finding in result.security_findings:
            findings.append({
                "id": finding.finding_id,
                "risk": finding.risk_level.value,
                "title": finding.title,
                "description": finding.description,
            })

        return DiscoveredAsset(
            asset_id=f"asset_{self._asset_counter:04d}",
            asset_type=AssetType.IOS_APP,
            name=result.bundle_id or result.ipa_path,
            metadata={
                "version_name": result.version_name,
                "version_number": result.version_number,
                "url_schemes": [s.scheme for s in result.url_schemes],
                "permissions": list(result.permissions.keys()),
            },
            discovery_timestamp=time.time(),
            security_findings=findings,
        )

    def _create_asset_from_mqtt(
        self,
        result: MQTTScanResult,
        host: str,
        port: int,
    ) -> DiscoveredAsset:
        """Create asset from MQTT scan result.

        Args:
            result: MQTT scan result.
            host: Broker host.
            port: Broker port.

        Returns:
            DiscoveredAsset object.
        """
        self._asset_counter += 1

        findings = []
        for finding in result.security_findings:
            findings.append({
                "id": f"mqtt_{self._asset_counter:04d}",
                "risk": "high" if "anonymous" in finding.lower() else "medium",
                "title": finding,
                "description": finding,
            })

        return DiscoveredAsset(
            asset_id=f"asset_{self._asset_counter:04d}",
            asset_type=AssetType.MQTT_BROKER,
            name=f"MQTT Broker: {host}:{port}",
            host=host,
            port=port,
            metadata={
                "anonymous_access": result.is_anonymous_access,
                "default_credentials": result.default_credentials_work,
                "discovered_topics": result.discovered_topics,
                "tls_enabled": result.broker_info.is_tls_enabled if result.broker_info else False,
            },
            discovery_timestamp=time.time(),
            security_findings=findings,
        )

    def _create_asset_from_coap(
        self,
        result: CoAPScanResult,
        host: str,
        port: int,
    ) -> DiscoveredAsset:
        """Create asset from CoAP scan result.

        Args:
            result: CoAP scan result.
            host: Device host.
            port: Device port.

        Returns:
            DiscoveredAsset object.
        """
        self._asset_counter += 1

        findings = []
        if result.device_info:
            for finding in result.device_info.security_findings:
                findings.append({
                    "id": f"coap_{self._asset_counter:04d}",
                    "risk": "high" if "sensitive" in finding.lower() else "medium",
                    "title": finding,
                    "description": finding,
                })

        return DiscoveredAsset(
            asset_id=f"asset_{self._asset_counter:04d}",
            asset_type=AssetType.COAP_DEVICE,
            name=f"CoAP Device: {host}:{port}",
            host=host,
            port=port,
            metadata={
                "supports_discovery": result.device_info.supports_discovery if result.device_info else False,
                "requires_auth": result.device_info.requires_auth if result.device_info else False,
                "total_resources": result.total_resources,
                "sensitive_resources": result.sensitive_resources,
            },
            discovery_timestamp=time.time(),
            security_findings=findings,
        )

    def _create_asset_from_modbus(
        self,
        result: ModbusScanResult,
        host: str,
        port: int,
        unit_id: int,
    ) -> DiscoveredAsset:
        """Create asset from Modbus scan result.

        Args:
            result: Modbus scan result.
            host: Device host.
            port: Device port.
            unit_id: Unit identifier.

        Returns:
            DiscoveredAsset object.
        """
        self._asset_counter += 1

        findings = []
        if result.device_info:
            for finding in result.device_info.security_findings:
                findings.append({
                    "id": f"modbus_{self._asset_counter:04d}",
                    "risk": "critical" if "writable" in finding.lower() else "medium",
                    "title": finding,
                    "description": finding,
                })

        return DiscoveredAsset(
            asset_id=f"asset_{self._asset_counter:04d}",
            asset_type=AssetType.MODBUS_DEVICE,
            name=f"Modbus Device: {host}:{port}",
            host=host,
            port=port,
            metadata={
                "unit_id": unit_id,
                "vendor": result.device_info.vendor_name if result.device_info else "",
                "product_code": result.device_info.product_code if result.device_info else "",
                "writable_registers": len(result.writable_registers),
            },
            discovery_timestamp=time.time(),
            security_findings=findings,
        )

    def _create_asset_from_ble(self, device: BLEDeviceInfo) -> DiscoveredAsset:
        """Create asset from BLE device info.

        Args:
            device: BLE device information.

        Returns:
            DiscoveredAsset object.
        """
        self._asset_counter += 1

        findings = []
        for finding in device.security_findings:
            findings.append({
                "id": f"ble_{self._asset_counter:04d}",
                "risk": "high" if "unencrypted" in finding.lower() else "low",
                "title": finding,
                "description": finding,
            })

        return DiscoveredAsset(
            asset_id=f"asset_{self._asset_counter:04d}",
            asset_type=AssetType.BLE_DEVICE,
            name=device.name or device.address,
            metadata={
                "address": device.address,
                "rssi": device.rssi,
                "services_count": len(device.services),
            },
            discovery_timestamp=time.time(),
            security_findings=findings,
        )

    async def _register_asset(self, asset: DiscoveredAsset) -> None:
        """Register a discovered asset with the platform.

        Args:
            asset: Asset to register.
        """
        self._discovered_assets.append(asset)

        if self._asset_registry_callback:
            try:
                await self._asset_registry_callback(asset)
            except Exception as e:
                logger.error(f"Failed to register asset: {e}")

    async def _trigger_apk_pocs(self, result: APKAnalysisResult) -> None:
        """Trigger relevant PoCs based on APK analysis.

        Args:
            result: APK analysis result.
        """
        for sdk in result.detected_sdks:
            if sdk.has_known_vulnerabilities:
                await self._trigger_poc("sdk_vulnerability", {
                    "sdk_name": sdk.sdk_name,
                    "package_path": sdk.package_path,
                    "vulnerability_details": sdk.vulnerability_details,
                })

        for component in result.exported_components:
            if not component.permission:
                await self._trigger_poc("exported_component", {
                    "component_name": component.name,
                    "component_type": component.component_type,
                })

    async def _trigger_ipa_pocs(self, result: IPAAnalysisResult) -> None:
        """Trigger relevant PoCs based on IPA analysis.

        Args:
            result: IPA analysis result.
        """
        for finding in result.security_findings:
            if "ATS" in finding.title:
                await self._trigger_poc("ats_misconfiguration", {
                    "finding_id": finding.finding_id,
                    "title": finding.title,
                })

        if result.macho_info and result.macho_info.has_private_api:
            await self._trigger_poc("private_api_usage", {
                "binary": result.macho_info.file_name,
            })

    async def _trigger_poc(self, poc_type: str, params: Dict[str, Any]) -> None:
        """Trigger a PoC execution.

        Args:
            poc_type: Type of PoC to trigger.
            params: PoC parameters.
        """
        if self._poc_trigger_callback:
            try:
                await self._poc_trigger_callback(poc_type, params)
            except Exception as e:
                logger.error(f"Failed to trigger PoC: {e}")

    def _add_sensitive_findings(
        self,
        apk_result: APKAnalysisResult,
        sensitive_result: DetectionResult,
    ) -> None:
        """Add sensitive information findings to APK result.

        Args:
            apk_result: APK analysis result.
            sensitive_result: Sensitive detection result.
        """
        for secret in sensitive_result.detected_secrets:
            finding = APKSecurityFinding(
                finding_id=f"SENS_{secret.secret_id}",
                risk_level=self._map_risk(secret.risk_level.value),
                category="Sensitive Information",
                title=f"Hardcoded {secret.secret_type.value} detected",
                description=f"Found {secret.secret_type.value} in {secret.location}",
                recommendation="Remove hardcoded secrets and use secure storage",
                affected_component=secret.location,
            )
            apk_result.security_findings.append(finding)

    def _add_sensitive_findings_to_ipa(
        self,
        ipa_result: IPAAnalysisResult,
        sensitive_result: DetectionResult,
    ) -> None:
        """Add sensitive information findings to IPA result.

        Args:
            ipa_result: IPA analysis result.
            sensitive_result: Sensitive detection result.
        """
        for secret in sensitive_result.detected_secrets:
            finding = IPASecurityFinding(
                finding_id=f"SENS_{secret.secret_id}",
                risk_level=self._map_risk(secret.risk_level.value),
                category="Sensitive Information",
                title=f"Hardcoded {secret.secret_type.value} detected",
                description=f"Found {secret.secret_type.value} in {secret.location}",
                recommendation="Remove hardcoded secrets and use secure storage",
                affected_component=secret.location,
            )
            ipa_result.security_findings.append(finding)

    def _map_risk(self, risk_str: str) -> Any:
        """Map risk string to SecurityRisk enum.

        Args:
            risk_str: Risk level string.

        Returns:
            Mapped SecurityRisk value.
        """
        from .mobile_apk_parser import SecurityRisk

        risk_map: Dict[str, SecurityRisk] = {
            "critical": SecurityRisk.CRITICAL,
            "high": SecurityRisk.HIGH,
            "medium": SecurityRisk.MEDIUM,
            "low": SecurityRisk.LOW,
            "info": SecurityRisk.INFO,
        }

        return risk_map.get(risk_str, SecurityRisk.INFO)

    def _generate_summary(self) -> str:
        """Generate executive summary for the report.

        Returns:
            Summary string.
        """
        total_assets = len(self._discovered_assets)
        mobile_assets = sum(
            1 for a in self._discovered_assets
            if a.asset_type in (AssetType.ANDROID_APP, AssetType.IOS_APP)
        )
        iot_assets = sum(
            1 for a in self._discovered_assets
            if a.asset_type in (
                AssetType.MQTT_BROKER, AssetType.COAP_DEVICE,
                AssetType.MODBUS_DEVICE, AssetType.IOT_GATEWAY,
            )
        )
        wireless_assets = sum(
            1 for a in self._discovered_assets
            if a.asset_type == AssetType.BLE_DEVICE
        )

        return (
            f"Discovered {total_assets} assets: {mobile_assets} mobile applications, "
            f"{iot_assets} IoT devices, and {wireless_assets} wireless devices."
        )

    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations.

        Returns:
            List of recommendation strings.
        """
        recommendations = []

        for asset in self._discovered_assets:
            if asset.asset_type == AssetType.ANDROID_APP:
                recommendations.append(
                    f"Review exported components in {asset.name}"
                )
            elif asset.asset_type == AssetType.MQTT_BROKER:
                if asset.metadata.get("anonymous_access"):
                    recommendations.append(
                        f"Disable anonymous access on MQTT broker {asset.host}"
                    )
            elif asset.asset_type == AssetType.MODBUS_DEVICE:
                if asset.metadata.get("writable_registers", 0) > 0:
                    recommendations.append(
                        f"Restrict write access on Modbus device {asset.host}"
                    )

        if not recommendations:
            recommendations.append("No critical recommendations at this time")

        return recommendations

    def _asset_to_report_entry(self, asset: DiscoveredAsset) -> Dict[str, Any]:
        """Convert asset to report entry format.

        Args:
            asset: Asset to convert.

        Returns:
            Dictionary with report entry data.
        """
        return {
            "asset_id": asset.asset_id,
            "asset_type": asset.asset_type.value,
            "name": asset.name,
            "host": asset.host,
            "port": asset.port,
            "findings_count": len(asset.security_findings),
            "findings": asset.security_findings,
            "metadata": asset.metadata,
        }
