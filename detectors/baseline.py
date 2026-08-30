from dataclasses import dataclass

from features.flow_features import FlowFeatures
from schemas.alert import DetectionAlert


@dataclass(frozen=True)
class BaselineConfig:
    syn_flood_min_packet_count: int = 20
    syn_flood_min_duration: float = 1.0
    syn_flood_min_packet_rate: float = 50.0
    syn_flood_min_syn_ratio: float = 0.8
    syn_flood_max_ack_ratio: float = 0.1
    syn_flood_severity: str = "HIGH"


class BaselineDetector:
    def __init__(
        self,
        config: BaselineConfig | None = None,
    ):
        self.config = config or BaselineConfig()

    def detect(
        self,
        features: FlowFeatures,
        flow_id: str,
        timestamp: str,
    ) -> list[DetectionAlert]:
        alerts = []

        syn_flood_alert = self._detect_syn_flood(
            features=features,
            flow_id=flow_id,
            timestamp=timestamp,
        )

        if syn_flood_alert is not None:
            alerts.append(syn_flood_alert)

        return alerts

    def _detect_syn_flood(
        self,
        features: FlowFeatures,
        flow_id: str,
        timestamp: str,
    ) -> DetectionAlert | None:
        config = self.config

        evidence = {
            "packet_rate": features.packet_rate,
            "syn_ratio": features.syn_ratio,
            "ack_ratio": features.ack_ratio,
            "packet_count": features.packet_count,
            "duration": features.duration,
            "thresholds": {
                "min_packet_count": config.syn_flood_min_packet_count,
                "min_duration": config.syn_flood_min_duration,
                "min_packet_rate": config.syn_flood_min_packet_rate,
                "min_syn_ratio": config.syn_flood_min_syn_ratio,
                "max_ack_ratio": config.syn_flood_max_ack_ratio,
            },
        }

        if not self._matches_syn_flood(features):
            return None

        return DetectionAlert(
            timestamp=timestamp,
            flow_id=flow_id,
            threat_class="SYN_FLOOD_SUSPECTED",
            confidence=self._syn_flood_confidence(features),
            severity=config.syn_flood_severity,
            evidence=evidence,
        )

    def _matches_syn_flood(
        self,
        features: FlowFeatures,
    ) -> bool:
        config = self.config

        return (
            features.packet_count >= config.syn_flood_min_packet_count
            and features.duration >= config.syn_flood_min_duration
            and features.packet_rate >= config.syn_flood_min_packet_rate
            and features.syn_ratio >= config.syn_flood_min_syn_ratio
            and features.ack_ratio <= config.syn_flood_max_ack_ratio
        )

    def _syn_flood_confidence(
        self,
        features: FlowFeatures,
    ) -> float:
        config = self.config

        scores = [
            _min_threshold_score(
                features.packet_count,
                config.syn_flood_min_packet_count,
            ),
            _min_threshold_score(
                features.duration,
                config.syn_flood_min_duration,
            ),
            _min_threshold_score(
                features.packet_rate,
                config.syn_flood_min_packet_rate,
            ),
            _min_threshold_score(
                features.syn_ratio,
                config.syn_flood_min_syn_ratio,
            ),
            _max_threshold_score(
                features.ack_ratio,
                config.syn_flood_max_ack_ratio,
            ),
        ]

        confidence = sum(scores) / len(scores)
        return max(0.0, min(1.0, round(confidence, 4)))


def _min_threshold_score(
    observed: float,
    threshold: float,
) -> float:
    if threshold <= 0:
        return 1.0

    return max(0.0, min(1.0, observed / threshold))


def _max_threshold_score(
    observed: float,
    threshold: float,
) -> float:
    if threshold <= 0:
        return 1.0 if observed <= 0 else 0.0

    return max(0.0, min(1.0, (threshold - observed) / threshold))
