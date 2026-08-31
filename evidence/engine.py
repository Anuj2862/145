"""Evidence Engine (Member 3).

Responsible for translating raw numerical detector indicators, entity baseline
deviations, and multi-signal correlations into human-readable, explainable
evidence chains and analyst recommendations.
"""

from typing import List, Dict, Any, Optional
from schemas import DetectionSignal, ThreatClass, Severity, ThreatStage


class EvidenceEngine:
    """Generates explainable evidence items, threat stage categorizations, and recommendations."""

    # Threat class to MITRE / Cyber Kill Chain attack stage mapping
    STAGE_MAPPING: Dict[ThreatClass, str] = {
        ThreatClass.RECON_PORT_SCAN: "RECONNAISSANCE",
        ThreatClass.DGA_DNS_TUNNELLING: "COMMAND_AND_CONTROL_STAGING",
        ThreatClass.BOTNET_C2_BEACONING: "C2_ESTABLISHMENT",
        ThreatClass.ENCRYPTED_MALWARE: "MALWARE_EXECUTION",
        ThreatClass.DATA_EXFILTRATION: "EXFILTRATION",
        ThreatClass.VOLUMETRIC_DDOS: "IMPACT_DENIAL_OF_SERVICE",
        ThreatClass.UNKNOWN_ANOMALY: "ANOMALOUS_BEHAVIOUR",
    }

    RECOMMENDATION_MAPPING: Dict[ThreatClass, str] = {
        ThreatClass.VOLUMETRIC_DDOS: "Apply traffic rate limiting and upstream filter rules at gateway edge.",
        ThreatClass.RECON_PORT_SCAN: "Inspect source host for unauthorized discovery utilities or scanning tools.",
        ThreatClass.BOTNET_C2_BEACONING: "Isolate host endpoint; perform memory and process inspection for persistent C2 implant.",
        ThreatClass.DGA_DNS_TUNNELLING: "Sinkhole resolving domains and inspect local resolver logs for encoded tunnel queries.",
        ThreatClass.ENCRYPTED_MALWARE: "Correlate host process hash with JA3/JA4 fingerprint and terminate suspect process.",
        ThreatClass.DATA_EXFILTRATION: "Sever outbound communication path for host and audit transferred data volumes.",
        ThreatClass.UNKNOWN_ANOMALY: "Conduct forensic capture review on host baseline deviation.",
    }

    @classmethod
    def map_to_threat_stage(cls, signal: DetectionSignal) -> ThreatStage:
        """Map a DetectionSignal to a structured ThreatStage in the attack lifecycle."""
        stage_name = cls.STAGE_MAPPING.get(signal.threat_class, "UNKNOWN_STAGE")
        return ThreatStage(
            stage=stage_name,
            timestamp_iso=signal.timestamp_iso,
            threat_class=signal.threat_class,
            confidence=signal.confidence,
        )

    @classmethod
    def generate_evidence_items(
        cls,
        signal: DetectionSignal,
        baseline_deviation: Optional[float] = None,
        is_new_destination: Optional[bool] = None,
    ) -> List[str]:
        """Generate human-readable evidence statements from signal indicators."""
        evidence: List[str] = []
        ind = signal.indicators or {}
        tc = signal.threat_class

        if tc == ThreatClass.VOLUMETRIC_DDOS:
            if "packets_per_sec" in ind:
                evidence.append(f"High packet velocity: {ind['packets_per_sec']:.1f} packets/sec")
            if "syn_ratio" in ind:
                evidence.append(f"Abnormal SYN flag ratio: {ind['syn_ratio'] * 100:.1f}%")
            if "bytes_per_sec" in ind:
                evidence.append(f"Bandwidth volume: {ind['bytes_per_sec'] / 1024:.1f} KB/s")

        elif tc == ThreatClass.BOTNET_C2_BEACONING:
            if "periodicity_score" in ind:
                evidence.append(f"High connection periodicity: score {ind['periodicity_score']:.2f} / 1.00")
            if "jitter_pct" in ind:
                evidence.append(f"Low timing jitter: {ind['jitter_pct']:.1f}%")
            if "connection_count" in ind:
                evidence.append(f"Persistent repeated callbacks: {ind['connection_count']} connections")

        elif tc == ThreatClass.DGA_DNS_TUNNELLING:
            if "entropy_mean" in ind:
                evidence.append(f"Elevated domain character entropy: {ind['entropy_mean']:.2f}")
            if "query_length_mean" in ind:
                evidence.append(f"Abnormal query string length: mean {ind['query_length_mean']:.1f} chars")
            if "nxdomain_count" in ind and ind["nxdomain_count"] > 0:
                evidence.append(f"High NXDOMAIN failure frequency: {ind['nxdomain_count']} failures")

        elif tc == ThreatClass.ENCRYPTED_MALWARE:
            if "ja3_hash" in ind:
                evidence.append(f"Observable TLS JA3 fingerprint: {ind['ja3_hash']}")
            if "ja4_hash" in ind:
                evidence.append(f"Observable TLS JA4 fingerprint: {ind['ja4_hash']}")
            if "sni" in ind:
                evidence.append(f"Target Server Name Indication (SNI): {ind['sni']}")

        elif tc == ThreatClass.RECON_PORT_SCAN:
            if "destination_ports_scanned" in ind:
                evidence.append(f"Rapid port discovery sweep: {ind['destination_ports_scanned']} unique ports")
            if "fan_out" in ind:
                evidence.append(f"High destination fan-out: {ind['fan_out']} target IPs")

        elif tc == ThreatClass.DATA_EXFILTRATION:
            if "outbound_bytes" in ind:
                evidence.append(f"Large outbound transfer volume: {ind['outbound_bytes'] / (1024*1024):.2f} MB")
            if "upload_download_ratio" in ind:
                evidence.append(f"Asymmetric outbound byte ratio: {ind['upload_download_ratio']:.1f}")

        # Add entity baseline context if available
        if baseline_deviation is not None and baseline_deviation > 2.0:
            evidence.append(f"Traffic velocity deviates significantly (+{baseline_deviation:.1f}σ) from host baseline")

        if is_new_destination:
            evidence.append("Target endpoint is a newly observed destination for this host")

        if not evidence:
            evidence.append(f"Automated detector signal: {signal.detector_type.value} confidence {signal.confidence:.2f}")

        return evidence

    @classmethod
    def get_recommended_action(cls, threat_class: ThreatClass) -> str:
        """Get actionable analyst recommendation for a given threat category."""
        return cls.RECOMMENDATION_MAPPING.get(threat_class, "Perform forensic investigation on active host.")
