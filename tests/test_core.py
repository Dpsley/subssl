import unittest
from subssl.nicru import NicRecord, collect_zone_names, record_name_to_fqdn

class CoreTests(unittest.TestCase):
    def test_names(self):
        self.assertEqual(record_name_to_fqdn("api", "example.com"), "api.example.com")
        self.assertEqual(record_name_to_fqdn("@", "example.com"), "example.com")
        self.assertEqual(record_name_to_fqdn("api.example.com.", "example.com"), "api.example.com")

    def test_collect(self):
        names = collect_zone_names([
            NicRecord("api", "A"), NicRecord("api", "AAAA"), NicRecord("www", "CNAME"),
            NicRecord("_acme-challenge", "TXT"), NicRecord("foo._acme-challenge", "TXT"),
            NicRecord("api.internal", "A"), NicRecord("*", "A"),
        ], "example.com")
        self.assertEqual(names["api.example.com"], {"A", "AAAA"})
        self.assertIn("www.example.com", names)
        self.assertNotIn("_acme-challenge.example.com", names)
        self.assertNotIn("foo._acme-challenge.example.com", names)
        self.assertNotIn("api.internal.example.com", names)
        self.assertNotIn("*.example.com", names)

if __name__ == "__main__":
    unittest.main()
