"""
Tests for SwitchGate AI Netpilot Network Engine (Deep-Level Kernel & Hardware Integration)
"""
import sys
import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.core.ai_netpilot import ai_netpilot


class TestAINetpilot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_engine_initialization_and_status(self):
        status = ai_netpilot.get_status()
        self.assertIn("master_enabled", status)
        self.assertIn("features", status)
        self.assertIn("metrics", status)
        self.assertIn("wlan", status)
        self.assertIn("switcher", status)
        self.assertIn("booster", status)

        features = status["features"]
        self.assertIn("rf_antenna", features)
        self.assertIn("network_switcher", features)
        self.assertIn("network_booster", features)
        self.assertIn("super_wifi", features)

        metrics = status["metrics"]
        self.assertIn("browsing_lag_optimisations", metrics)
        self.assertIn("browsing_lag_time_reduced", metrics)
        self.assertIn("missed_calls_prevented", metrics)
        self.assertIn("gaming_lag_time_reduced", metrics)

    def test_02_feature_toggles(self):
        # Test toggling rf_antenna
        curr = ai_netpilot.rf_antenna_enabled
        new_state = ai_netpilot.toggle_feature("rf_antenna", not curr)
        self.assertEqual(new_state, not curr)
        # Restore
        ai_netpilot.toggle_feature("rf_antenna", curr)

        # Test toggling network_switcher
        curr_sw = ai_netpilot.network_switcher_enabled
        new_sw = ai_netpilot.toggle_feature("network_switcher", not curr_sw)
        self.assertEqual(new_sw, not curr_sw)
        ai_netpilot.toggle_feature("network_switcher", curr_sw)

        # Test toggling network_booster
        curr_nb = ai_netpilot.network_booster_enabled
        new_nb = ai_netpilot.toggle_feature("network_booster", not curr_nb)
        self.assertEqual(new_nb, not curr_nb)
        ai_netpilot.toggle_feature("network_booster", curr_nb)

        # Test toggling super_wifi
        curr_wifi = ai_netpilot.super_wifi_enabled
        new_wifi = ai_netpilot.toggle_feature("super_wifi", not curr_wifi)
        self.assertEqual(new_wifi, not curr_wifi)
        ai_netpilot.toggle_feature("super_wifi", curr_wifi)

    def test_03_deep_optimization_sweep(self):
        res = ai_netpilot.optimize_now()
        self.assertTrue(res.get("success"))
        self.assertIn("latency_ms", res)
        self.assertIn("kernel_tuning", res)
        self.assertIn("metrics", res)
        print(f"\n[Test] Deep optimization latency: {res['latency_ms']}ms, elapsed: {res['elapsed_ms']}ms")

    def test_04_rest_api_endpoints(self):
        # 1. GET /api/netpilot/status
        resp = self.client.get("/api/netpilot/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue("features" in data)

        # 2. POST /api/netpilot/toggle_feature
        resp2 = self.client.post("/api/netpilot/toggle_feature", json={"feature": "rf_antenna", "enable": True})
        self.assertEqual(resp2.status_code, 200)
        self.assertTrue(resp2.json().get("success"))

        # 3. POST /api/netpilot/optimize_now
        resp3 = self.client.post("/api/netpilot/optimize_now")
        self.assertEqual(resp3.status_code, 200)
        data3 = resp3.json()
        self.assertTrue(data3.get("success"))
        self.assertIn("latency_ms", data3)

    def test_05_telemetry_snapshot_contains_netpilot(self):
        resp = self.client.get("/api/telemetry/live")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("netpilot", data)
        self.assertIn("features", data["netpilot"])
        self.assertIn("metrics", data["netpilot"])


if __name__ == "__main__":
    unittest.main()
