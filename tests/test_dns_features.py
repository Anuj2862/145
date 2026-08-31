import unittest
import math
from features.dns_features import DNSRecord, extract_dns_features, calculate_shannon_entropy, has_subdomain

class TestDNSFeatures(unittest.TestCase):
    
    def test_correct_mathematical_entropy_calculation(self):
        """Verify entropy calculation against known mathematical truths."""
        # 1 character (p=1.0) -> log2(1) = 0
        self.assertEqual(calculate_shannon_entropy("a"), 0.0)
        # All same characters -> 0
        self.assertEqual(calculate_shannon_entropy("aaaa"), 0.0)
        # 2 unique chars, equal prob (p=0.5) -> -2 * (0.5 * -1) = 1.0
        self.assertEqual(calculate_shannon_entropy("ab"), 1.0)
        # 4 unique chars, equal prob (p=0.25) -> -4 * (0.25 * -2) = 2.0
        self.assertEqual(calculate_shannon_entropy("abcd"), 2.0)
        
    def test_normal_domains(self):
        """Test feature extraction on normal domain traffic."""
        records = [
            DNSRecord("example.com", "NOERROR", "A"),
            DNSRecord("google.com", "NOERROR", "AAAA")
        ]
        features = extract_dns_features(records)
        self.assertEqual(features.query_length_mean, 10.5) # (11 + 10) / 2
        self.assertEqual(features.nxdomain_count, 0)
        self.assertEqual(features.txt_record_ratio, 0.0)
        self.assertEqual(features.subdomain_count, 0)
        self.assertGreater(features.entropy_mean, 2.0)

    def test_high_entropy_domain_strings(self):
        """Test handling of high-entropy (DGA-like) domains."""
        records = [
            DNSRecord("x1y2z3a4b5c6d7e8.com", "NOERROR", "A"),
            DNSRecord("qwert12345.com", "NOERROR", "A")
        ]
        features = extract_dns_features(records)
        
        # Ensure entropy is noticeably high
        self.assertGreater(features.entropy_mean, 3.0)

    def test_nxdomain_counting(self):
        """Test accurate counting of NXDOMAIN responses."""
        records = [
            DNSRecord("legit.com", "NOERROR", "A"),
            DNSRecord("bad1.com", "NXDOMAIN", "A"),
            DNSRecord("bad2.com", "nxdomain", "A") # Case insensitive check
        ]
        features = extract_dns_features(records)
        self.assertEqual(features.nxdomain_count, 2)

    def test_txt_ratio(self):
        """Test accurate calculation of TXT record ratio."""
        records = [
            DNSRecord("test.com", "NOERROR", "TXT"),
            DNSRecord("test.com", "NOERROR", "A"),
            DNSRecord("test.com", "NOERROR", "TXT"),
            DNSRecord("test.com", "NOERROR", "AAAA"),
        ]
        features = extract_dns_features(records)
        self.assertEqual(features.txt_record_ratio, 0.5)

    def test_subdomain_counting(self):
        """Test the heuristic subdomain counting logic."""
        records = [
            DNSRecord("example.com", "NOERROR", "A"),             # 0
            DNSRecord("www.example.com", "NOERROR", "A"),         # 1
            DNSRecord("api.v1.example.com", "NOERROR", "A"),      # 1
            DNSRecord("amazon.co.uk", "NOERROR", "A"),            # 0 (special ccTLD case)
            DNSRecord("shop.amazon.co.uk", "NOERROR", "A"),       # 1
        ]
        features = extract_dns_features(records)
        self.assertEqual(features.subdomain_count, 3)

    def test_empty_input(self):
        """Test handling of empty record list."""
        features = extract_dns_features([])
        self.assertIsNone(features.query_length_mean)
        self.assertIsNone(features.entropy_mean)
        self.assertEqual(features.nxdomain_count, 0)
        self.assertIsNone(features.txt_record_ratio)
        self.assertIsNone(features.subdomain_count)

    def test_empty_query(self):
        """Test handling of records with empty query strings."""
        records = [
            DNSRecord("", "NOERROR", "A"),
            DNSRecord("example.com", "NOERROR", "A")
        ]
        features = extract_dns_features(records)
        # Should exclude the empty query from length and entropy means
        self.assertEqual(features.query_length_mean, 11.0)
        self.assertEqual(features.subdomain_count, 0)
        
    def test_malformed_input_handling(self):
        """Test handling of None or strictly invalid query strings (if they slipped in)."""
        records = [
            DNSRecord(None, "NOERROR", "A"), # type: ignore
            DNSRecord("example.com", "NOERROR", "A")
        ]
        features = extract_dns_features(records)
        self.assertEqual(features.query_length_mean, 11.0)

    def test_deterministic_output(self):
        """Verify that identical inputs produce identical feature vectors."""
        records = [
            DNSRecord("test.com", "NOERROR", "A"),
            DNSRecord("sub.test.com", "NXDOMAIN", "TXT")
        ]
        f1 = extract_dns_features(records)
        f2 = extract_dns_features(records)
        
        self.assertEqual(f1.query_length_mean, f2.query_length_mean)
        self.assertEqual(f1.entropy_mean, f2.entropy_mean)
        self.assertEqual(f1.nxdomain_count, f2.nxdomain_count)
        self.assertEqual(f1.txt_record_ratio, f2.txt_record_ratio)
        self.assertEqual(f1.subdomain_count, f2.subdomain_count)
