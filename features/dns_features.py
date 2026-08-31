import math
from typing import List, Optional
from collections import Counter
from dataclasses import dataclass
from schemas import DNSFeatures

@dataclass
class DNSRecord:
    """
    Internal representation of a passively observed DNS query/response.
    This avoids polluting the shared FlowEvent schema with unrelated fields.
    """
    query: str
    rcode: str  # e.g., "NOERROR", "NXDOMAIN"
    qtype: str  # e.g., "A", "TXT", "AAAA", "CNAME"


def calculate_shannon_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string.
    Formula: H = - sum(p * log2(p)) where p is the frequency of each character.
    Returns 0.0 for empty strings.
    """
    if not s:
        return 0.0
    counter = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def has_subdomain(query: str) -> bool:
    """
    Conservative heuristic to determine if a query contains subdomains beyond
    the registrable base domain.
    
    Heuristic:
    - Splits by '.'
    - If <= 2 parts (e.g., example.com), no subdomain.
    - If 3 parts, checks if the TLD is a known 2-part structure (like .co.uk, .com.br).
      If so, no subdomain. Otherwise, yes.
    - If > 3 parts, assumes yes.
    """
    if not query:
        return False
    parts = [p for p in query.split('.') if p]
    if len(parts) <= 2:
        return False
        
    if len(parts) == 3:
        # Check common ccTLD second-level domains
        second_level = parts[-2].lower()
        if second_level in ("co", "com", "org", "net", "gov", "ac", "edu") and len(parts[-1]) == 2:
            return False
            
    return True


def extract_dns_features(records: List[DNSRecord]) -> DNSFeatures:
    """
    Extract DNSFeatures from a sequence of DNSRecord objects.
    """
    if not records:
        return DNSFeatures(
            query_length_mean=None,
            entropy_mean=None,
            nxdomain_count=0,
            txt_record_ratio=None,
            subdomain_count=None
        )

    total_queries = len(records)
    valid_queries = [r.query for r in records if r.query]
    num_valid = len(valid_queries)

    # 1. query_length_mean
    # Measured as the number of characters in the full domain string
    query_length_mean = None
    if num_valid > 0:
        query_length_mean = sum(len(q) for q in valid_queries) / float(num_valid)

    # 2. entropy_mean
    # Mean of Shannon entropy calculated on the query strings
    entropy_mean = None
    if num_valid > 0:
        entropy_mean = sum(calculate_shannon_entropy(q) for q in valid_queries) / float(num_valid)

    # 3. nxdomain_count
    nxdomain_count = sum(1 for r in records if r.rcode.upper() == "NXDOMAIN")

    # 4. txt_record_ratio
    txt_record_ratio = None
    if total_queries > 0:
        txt_count = sum(1 for r in records if r.qtype.upper() == "TXT")
        txt_record_ratio = txt_count / float(total_queries)

    # 5. subdomain_count
    subdomain_count = None
    if num_valid > 0:
        subdomain_count = sum(1 for q in valid_queries if has_subdomain(q))

    return DNSFeatures(
        query_length_mean=query_length_mean,
        entropy_mean=entropy_mean,
        nxdomain_count=nxdomain_count,
        txt_record_ratio=txt_record_ratio,
        subdomain_count=subdomain_count
    )
