import unittest
from schemas import TLSFeatures
from features.tls_features import TLSMetadata, extract_tls_features

class TestTLSFeatures(unittest.TestCase):
    
    def test_complete_tls_metadata(self):
        """Test extraction when all metadata fields are present."""
        records = [
            TLSMetadata(
                ja3="771,4865-4866,0-23,29-23-24,0",
                ja4="t13d1516h2_8daaf6152771_b186095e22b6",
                sni="www.example.com",
                alpn="h2"
            )
        ]
        features = extract_tls_features(records)
        
        self.assertEqual(features.ja3_hash, "771,4865-4866,0-23,29-23-24,0")
        self.assertEqual(features.ja4_hash, "t13d1516h2_8daaf6152771_b186095e22b6")
        self.assertEqual(features.sni, "www.example.com")
        self.assertEqual(features.alpn, "h2")

    def test_missing_ja3(self):
        """Test safe extraction when JA3 is missing."""
        records = [TLSMetadata(ja4="t13", sni="test.com", alpn="http/1.1")]
        features = extract_tls_features(records)
        
        self.assertIsNone(features.ja3_hash)
        self.assertEqual(features.ja4_hash, "t13")

    def test_missing_ja4(self):
        """Test safe extraction when JA4 is missing."""
        records = [TLSMetadata(ja3="771", sni="test.com", alpn="http/1.1")]
        features = extract_tls_features(records)
        
        self.assertIsNone(features.ja4_hash)
        self.assertEqual(features.ja3_hash, "771")

    def test_missing_sni(self):
        """Test safe extraction when SNI is missing (e.g., bare IP connection)."""
        records = [TLSMetadata(ja3="771", ja4="t13", alpn="h2")]
        features = extract_tls_features(records)
        
        self.assertIsNone(features.sni)
        self.assertEqual(features.alpn, "h2")

    def test_missing_alpn(self):
        """Test safe extraction when ALPN is not negotiated."""
        records = [TLSMetadata(ja3="771", ja4="t13", sni="test.com")]
        features = extract_tls_features(records)
        
        self.assertIsNone(features.alpn)
        self.assertEqual(features.sni, "test.com")

    def test_empty_metadata_list(self):
        """Test handling of totally empty input list."""
        features = extract_tls_features([])
        
        self.assertIsNone(features.ja3_hash)
        self.assertIsNone(features.ja4_hash)
        self.assertIsNone(features.sni)
        self.assertIsNone(features.alpn)

    def test_empty_strings_handled_as_none(self):
        """Test that empty or whitespace-only strings are normalized to None."""
        records = [
            TLSMetadata(
                ja3="",
                ja4="   ",
                sni=" \t ",
                alpn=""
            )
        ]
        features = extract_tls_features(records)
        
        self.assertIsNone(features.ja3_hash)
        self.assertIsNone(features.ja4_hash)
        self.assertIsNone(features.sni)
        self.assertIsNone(features.alpn)

    def test_quic_partial_metadata(self):
        """Test QUIC connection which may only expose SNI and ALPN."""
        records = [
            TLSMetadata(sni="quic.example.com", alpn="h3")
        ]
        features = extract_tls_features(records)
        
        self.assertIsNone(features.ja3_hash)
        self.assertIsNone(features.ja4_hash)
        self.assertEqual(features.sni, "quic.example.com")
        self.assertEqual(features.alpn, "h3")

    def test_fingerprints_preserved_exactly(self):
        """Ensure fingerprints are treated as strict identifiers without modification."""
        exact_ja3 = "771,4865-4866-4867,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
        records = [TLSMetadata(ja3=exact_ja3)]
        features = extract_tls_features(records)
        
        self.assertEqual(features.ja3_hash, exact_ja3)

    def test_deterministic_output(self):
        """Verify identical inputs yield identical outputs."""
        records = [TLSMetadata(sni="foo.com", alpn="h2")]
        f1 = extract_tls_features(records)
        f2 = extract_tls_features(records)
        
        self.assertEqual(f1.sni, f2.sni)
        self.assertEqual(f1.alpn, f2.alpn)

    def test_tls_features_schema_validity(self):
        """Test that output maps cleanly to the Pydantic schema."""
        records = [TLSMetadata(sni="foo.com", alpn="h2")]
        features = extract_tls_features(records)
        
        self.assertIsInstance(features, TLSFeatures)
        # Verify JSON dump works without validation errors
        json_dump = features.model_dump_json()
        self.assertIn("foo.com", json_dump)

    def test_multiple_metadata_records(self):
        """Test batch processing fallback: fills missing fields from subsequent records."""
        records = [
            TLSMetadata(sni="missing-alpn.com", alpn=""), # ALPN is empty
            TLSMetadata(sni="ignored.com", alpn="h2")     # Should provide ALPN, SNI ignored because already populated
        ]
        features = extract_tls_features(records)
        
        self.assertEqual(features.sni, "missing-alpn.com")
        self.assertEqual(features.alpn, "h2")
