from typing import List, Optional
from dataclasses import dataclass
from schemas import TLSFeatures

@dataclass
class TLSMetadata:
    """
    Internal representation of passively observable TLS/QUIC handshake metadata.
    This structure keeps the shared FlowEvent schema clean of protocol-specific fields.
    
    PRIVACY/SECURITY GUARANTEE:
    This metadata is extracted solely from unencrypted ClientHello and ServerHello
    handshake packets. It does not require:
    - TLS decryption
    - Payload inspection
    - Man-in-the-Middle (MITM) interception
    - Private keys
    """
    ja3: Optional[str] = None
    ja4: Optional[str] = None
    sni: Optional[str] = None
    alpn: Optional[str] = None


def extract_tls_features(records: List[TLSMetadata]) -> TLSFeatures:
    """
    Extract TLSFeatures from a sequence of TLS/QUIC metadata observations.
    
    In a typical 5-tuple flow, there is only one TLS handshake. If multiple 
    records are present (e.g., due to connection reuse or parsing artifacts),
    this extractor populates the final feature vector using the first non-empty 
    value found for each attribute.
    
    QUIC Limitations:
    QUIC encrypts more of the handshake than TLS 1.2. Depending on the QUIC
    version and parser, SNI or ALPN might be visible, but JA3 is often
    inapplicable. This extractor safely handles partial/missing data by 
    leaving those fields as None. No fake fingerprints are fabricated.
    """
    features = TLSFeatures(
        ja3_hash=None,
        ja4_hash=None,
        sni=None,
        alpn=None
    )
    
    if not records:
        return features
        
    def _clean(val: Optional[str]) -> Optional[str]:
        if val is not None:
            cleaned = str(val).strip()
            if cleaned:
                return cleaned
        return None

    # Iterate through available records to fill missing metadata
    for record in records:
        if features.ja3_hash is None:
            features.ja3_hash = _clean(record.ja3)
        if features.ja4_hash is None:
            features.ja4_hash = _clean(record.ja4)
        if features.sni is None:
            features.sni = _clean(record.sni)
        if features.alpn is None:
            features.alpn = _clean(record.alpn)
            
    return features
