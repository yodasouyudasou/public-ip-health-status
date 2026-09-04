import json
import struct
import unittest
from pathlib import Path
from unittest.mock import patch

import monitor


class MonitorTests(unittest.TestCase):
    def test_dns_validation(self):
        query = struct.pack("!HHHHHH", 123, 256, 1, 0, 0, 0) + monitor.qname_bytes("example.com") + struct.pack("!HH", 1, 1)
        response = struct.pack("!HHHHHH", 123, 0x8180, 1, 1, 0, 0) + query[12:] + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + b"\x01\x02\x03\x04"
        self.assertTrue(monitor.validate_dns(response, query, 10)[0])
        self.assertFalse(monitor.validate_dns(b"short", query, 10)[0])
        self.assertFalse(monitor.validate_dns(b"\xff\xff" + response[2:], query, 10)[0])
        self.assertFalse(monitor.validate_dns(response[:3] + b"\x82" + response[4:], query, 10)[0])

    def test_ntp_validation(self):
        tx = b"12345678"
        response = bytearray(48)
        response[0] = 0x24
        response[1] = 2
        response[24:32] = tx
        response[40:48] = b"abcdefgh"
        self.assertTrue(monitor.validate_ntp(response, tx, 10)[0])
        self.assertFalse(monitor.validate_ntp(response, bytes(8), 10)[0])
        response[0] |= 0xc0
        self.assertFalse(monitor.validate_ntp(response, tx, 10)[0])
        response[0] = 0x24
        response[1] = 0
        self.assertFalse(monitor.validate_ntp(response, tx, 10)[0])

    def test_classification(self):
        target = {"address": "8.8.8.8", "method": "dns-recursive"}
        for protocol_ok, ping_status, expected in [(True, "down", "up"), (False, "up", "degraded"), (False, "down", "down")]:
            with patch.object(monitor, "dns_check", return_value=(protocol_ok, 12 if protocol_ok else None, "dns-response" if protocol_ok else "timeout")), patch.object(monitor, "icmp_check", return_value=(ping_status, None)):
                self.assertEqual(monitor.check_target(target)[1]["status"], expected)

    def test_ipv6_unavailable_is_not_down(self):
        with patch.object(monitor, "IPV6_AVAILABLE", False), patch.object(monitor, "icmp_check") as ping:
            _, result = monitor.check_target({"address": "2001:4860:4860::8888", "method": "dns-recursive"})
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(result["protocolStatus"], "unknown")
            self.assertIsNone(result["checkedAt"])
            ping.assert_not_called()

    def test_catalog_is_public_and_unique(self):
        targets = json.loads(Path("targets.json").read_text())
        self.assertEqual(len(targets), 169)
        self.assertEqual(len({t["address"] for t in targets}), 169)
        self.assertTrue(all(monitor.ipaddress.ip_address(t["address"]).is_global for t in targets))


if __name__ == "__main__":
    unittest.main()
