import uuid
from typing import List
from schemas import FlowEvent, FeatureVector
from features.flow_features import extract_flow_features
from features.temporal_features import extract_temporal_features

class FeatureExtractor:
    """
    Extracts features from incoming FlowEvents to construct a FeatureVector.
    """
    
    def __init__(self, window_size_sec: int = 5):
        self.window_size_sec = window_size_sec

    def extract(self, flow: FlowEvent) -> FeatureVector:
        """
        Convert a single FlowEvent into a FeatureVector.
        Currently extracts only FlowFeatures.
        """
        feature_id = f"fv-{uuid.uuid4().hex[:8]}"
        timestamp_iso = flow.end_time_iso
        flow_features = extract_flow_features(flow)
        
        return FeatureVector(
            feature_id=feature_id,
            entity_ip=flow.src_ip,
            flow_id=flow.flow_id,
            window_size_sec=self.window_size_sec,
            timestamp_iso=timestamp_iso,
            flow_features=flow_features
        )

    def extract_temporal(self, flows: List[FlowEvent]) -> FeatureVector:
        """
        Convert a sequence of FlowEvents into a FeatureVector including TemporalFeatures.
        The base FlowFeatures are extracted from the most recent/last flow in the sequence,
        assuming the sequence is chronologically ordered or at least representative of the entity.
        """
        if not flows:
            raise ValueError("Cannot extract temporal features from an empty list of flows.")
            
        # Use the last flow as the primary reference for base features
        primary_flow = flows[-1]
        
        feature_id = f"fv-{uuid.uuid4().hex[:8]}"
        timestamp_iso = primary_flow.end_time_iso
        
        flow_features = extract_flow_features(primary_flow)
        temporal_features = extract_temporal_features(flows)
        
        return FeatureVector(
            feature_id=feature_id,
            entity_ip=primary_flow.src_ip,
            flow_id=primary_flow.flow_id, # Optional representation of the most recent flow
            window_size_sec=self.window_size_sec,
            timestamp_iso=timestamp_iso,
            flow_features=flow_features,
            temporal_features=temporal_features
        )
