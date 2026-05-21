import unittest
import base64
from unittest.mock import patch

from backend import gti_client


class IocStreamReportTests(unittest.TestCase):
    def test_classify_ioc_risk_uses_score_thresholds_and_verdict_floor(self) -> None:
        self.assertEqual(
            gti_client.classify_ioc_risk(85, "unknown"),
            {
                "risk": "High",
                "recommended_action": "Investigate / block if confirmed",
            },
        )
        self.assertEqual(
            gti_client.classify_ioc_risk(35, "suspicious"),
            {
                "risk": "Medium",
                "recommended_action": "Investigate / monitor",
            },
        )
        self.assertEqual(
            gti_client.classify_ioc_risk(None, None),
            {"risk": "Unknown", "recommended_action": "Manual review"},
        )

    def test_build_ioc_stream_report_handles_missing_fields(self) -> None:
        stream_result = {
            "status_code": 200,
            "request_params": {"limit": 3},
            "raw_data": {
                "data": [
                    {
                        "id": "example.com",
                        "type": "domain",
                        "attributes": {
                            "gti_score": 92,
                            "gti_verdict": "malicious",
                            "source_type": "collection",
                        },
                    },
                    {
                        "id": "https://example.net/login",
                        "type": "url",
                        "attributes": {},
                    },
                    {
                        "id": "198.51.100.4",
                        "type": "ip_address",
                    },
                ]
            },
        }

        report = gti_client.build_ioc_stream_report(stream_result)

        self.assertEqual(report["summary"]["total_iocs"], 3)
        self.assertEqual(report["summary"]["high_risk"], 1)
        self.assertEqual(report["summary"]["unknown_risk"], 2)
        self.assertEqual(report["summary"]["main_entity_type"], "domain")
        self.assertEqual(report["top_indicators"][0]["value"], "example.com")
        self.assertEqual(report["top_indicators"][1]["severity"], "Unknown")
        self.assertTrue(report["definitions"])

    def test_build_ioc_stream_report_handles_empty_response(self) -> None:
        report = gti_client.build_ioc_stream_report(
            {"status_code": 200, "raw_data": {"data": []}}
        )

        self.assertEqual(report["summary"]["total_iocs"], 0)
        self.assertEqual(report["summary"]["main_entity_type"], "Unknown")
        self.assertEqual(report["charts"]["by_entity_type"], [])
        self.assertIn(
            "No IoC Stream notifications",
            " ".join(report["business_summary"]),
        )

    @patch("backend.gti_client._probe_json_endpoint")
    def test_fetch_ioc_stream_builds_filters(self, mock_probe) -> None:
        mock_probe.return_value = {
            "http_status": 200,
            "response_headers": {},
            "raw_json": {"data": []},
        }

        result = gti_client.fetch_ioc_stream(
            api_key="test-key",
            limit=40,
            entity_type="domain",
            origin="hunting",
            descriptors_only=True,
            start_date="2026-05-01",
            end_date="2026-05-21",
        )

        self.assertEqual(result["status_code"], 200)
        params = mock_probe.call_args.kwargs["params"]
        self.assertEqual(params["limit"], 40)
        self.assertEqual(params["filter"], "entity_type:domain origin:hunting")
        self.assertEqual(params["descriptors_only"], "true")
        self.assertEqual(params["order"], "date")
        self.assertEqual(result["request_params"]["requested_limit"], 40)
        self.assertEqual(result["request_params"]["api_page_limit"], 40)
        self.assertEqual(
            result["date_filtering"],
            {
                "start_date": "2026-05-01",
                "end_date": "2026-05-21",
                "api_filter_applied": False,
                "local_post_filtering_applied": False,
                "note": (
                    "Selected dates are shown for reporting context only; local post-filtering "
                    "not yet implemented."
                ),
            },
        )
        self.assertNotIn("2026-05-01", params.get("filter", ""))

    @patch("backend.gti_client._probe_json_endpoint")
    def test_fetch_ioc_stream_paginates_when_limit_exceeds_api_page_limit(
        self,
        mock_probe,
    ) -> None:
        def page(start: int, count: int, next_cursor: str | None = None) -> dict:
            payload = {
                "data": [
                    {
                        "id": f"example-{index}.com",
                        "type": "domain",
                        "attributes": {},
                    }
                    for index in range(start, start + count)
                ]
            }
            if next_cursor:
                payload["meta"] = {"next_cursor": next_cursor}
            return {
                "http_status": 200,
                "response_headers": {},
                "raw_json": payload,
            }

        mock_probe.side_effect = [
            page(0, 40, "cursor-1"),
            page(40, 40, "cursor-2"),
            page(80, 20),
        ]

        result = gti_client.fetch_ioc_stream(api_key="test-key", limit=100)

        self.assertEqual(mock_probe.call_count, 3)
        call_params = [call.kwargs["params"] for call in mock_probe.call_args_list]
        self.assertEqual(call_params[0]["limit"], 40)
        self.assertNotIn("cursor", call_params[0])
        self.assertEqual(call_params[1]["limit"], 40)
        self.assertEqual(call_params[1]["cursor"], "cursor-1")
        self.assertEqual(call_params[2]["limit"], 20)
        self.assertEqual(call_params[2]["cursor"], "cursor-2")
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["total_collected"], 100)
        self.assertEqual(len(result["raw_data"]["data"]), 100)
        self.assertEqual(result["request_params"]["requested_limit"], 100)

    @patch("backend.gti_client._probe_json_endpoint")
    def test_enrich_ioc_indicator_encodes_url_and_updates_risk(self, mock_probe) -> None:
        mock_probe.return_value = {
            "http_status": 200,
            "raw_json": {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 0, "suspicious": 3},
                        "reputation": -12,
                    }
                }
            },
        }
        indicator = {
            "value": "https://example.com/a?b=1",
            "entity_type": "url",
            "severity": "Unknown",
            "recommended_action": "Manual review",
        }

        enriched = gti_client.enrich_ioc_indicator("test-key", indicator)

        encoded_url_id = base64.urlsafe_b64encode(
            indicator["value"].encode("utf-8")
        ).decode("ascii").rstrip("=")
        self.assertTrue(mock_probe.call_args.kwargs["url"].endswith(f"/urls/{encoded_url_id}"))
        self.assertEqual(enriched["malicious"], 0)
        self.assertEqual(enriched["suspicious"], 3)
        self.assertEqual(enriched["reputation"], -12)
        self.assertEqual(enriched["severity"], "Medium")
        self.assertEqual(enriched["risk"], "Medium")
        self.assertEqual(enriched["recommended_action"], "Investigate / monitor")
        self.assertEqual(enriched["enrichment_status"], "success")

    @patch("backend.gti_client.enrich_ioc_indicator")
    def test_build_ioc_stream_report_enriches_only_top_10_returned(self, mock_enrich) -> None:
        def enrich_side_effect(api_key, indicator):
            updated = dict(indicator)
            updated["enrichment_status"] = "success"
            updated["malicious"] = 1
            updated["suspicious"] = 0
            updated["reputation"] = -20
            updated["severity"] = "High"
            updated["risk"] = "High"
            updated["recommended_action"] = "Investigate / block if confirmed"
            return updated

        mock_enrich.side_effect = enrich_side_effect
        stream_result = {
            "status_code": 200,
            "raw_data": {
                "data": [
                    {"id": f"example-{index}.com", "type": "domain", "attributes": {}}
                    for index in range(12)
                ]
            },
        }

        report = gti_client.build_ioc_stream_report(
            stream_result,
            api_key="test-key",
            enrich=True,
        )

        self.assertEqual(mock_enrich.call_count, 10)
        self.assertEqual(report["summary"]["total_iocs"], 12)
        self.assertEqual(report["summary"]["high_risk"], 10)
        self.assertEqual(report["summary"]["unknown_risk"], 2)
        self.assertEqual(report["technical_details"]["enrichment"]["attempted"], 10)
        self.assertEqual(report["technical_details"]["enrichment"]["succeeded"], 10)


if __name__ == "__main__":
    unittest.main()
