from typing import Optional
from schemas import FlowEvent, FlowFeatures

def extract_flow_features(flow: FlowEvent) -> FlowFeatures:
    """
    Extract flow velocity and cardinality features from a FlowEvent.
    
    Calculates:
    - packets_per_sec: packet_count / duration_sec (handles 0 duration safely)
    - bytes_per_sec: byte_count / duration_sec (handles 0 duration safely)
    - syn_ratio: (SYN count) / packet_count (if TCP, else None)
    - fan_out_dest_count: Always 1 in the context of a 5-tuple flow, but left as 1 for now.
    - dst_port_cardinality: Always 1 in the context of a 5-tuple flow.
    """
    duration = flow.duration_sec if flow.duration_sec > 0 else 1.0
    
    packets_per_sec = float(flow.packet_count) / duration
    bytes_per_sec = float(flow.byte_count) / duration
    
    syn_ratio: Optional[float] = None
    if flow.protocol == 6 and flow.tcp_flags is not None:
        if flow.packet_count > 0:
            syn_ratio = float(flow.tcp_flags.syn_count) / float(flow.packet_count)
        else:
            syn_ratio = 0.0
            
    # For a strict 5-tuple flow, dest IP and port cardinality is always 1
    # Note: If aggregating over a host across multiple flows, these would differ.
    fan_out_dest_count = 1
    dst_port_cardinality = 1
    
    return FlowFeatures(
        packets_per_sec=packets_per_sec,
        bytes_per_sec=bytes_per_sec,
        syn_ratio=syn_ratio,
        fan_out_dest_count=fan_out_dest_count,
        dst_port_cardinality=dst_port_cardinality
    )
