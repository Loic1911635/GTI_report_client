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

    def test_ioc_stream_analytics_use_only_enriched_indicators(self) -> None:
        analytics = gti_client.build_ioc_stream_analytics(
            [
                {
                    "value": "ignored.example",
                    "entity_type": "domain",
                    "severity": "High",
                    "malicious": 99,
                    "suspicious": 99,
                    "reputation": -99,
                    "enrichment_status": "not_requested",
                    "recommended_action": "Investigate / block if confirmed",
                },
                {
                    "value": "danger.example",
                    "entity_type": "domain",
                    "severity": "High",
                    "gti_score": 90,
                    "malicious": 3,
                    "suspicious": 0,
                    "reputation": -10,
                    "enrichment_status": "success",
                    "recommended_action": "Investigate / block if confirmed",
                },
                {
                    "value": "https://phish.example/login",
                    "entity_type": "url",
                    "severity": "Medium",
                    "gti_score": 60,
                    "malicious": 0,
                    "suspicious": 4,
                    "reputation": -20,
                    "enrichment_status": "success",
                    "recommended_action": "Investigate / monitor",
                },
                {
                    "value": "loader.bin",
                    "entity_type": "file",
                    "severity": "Low",
                    "malicious": 0,
                    "suspicious": 0,
                    "reputation": 1,
                    "enrichment_status": "success",
                    "recommended_action": "Monitor",
                },
                {
                    "value": "unknown.example",
                    "entity_type": "url",
                    "severity": "Unknown",
                    "malicious": 0,
                    "suspicious": 0,
                    "reputation": None,
                    "enrichment_status": "success",
                    "recommended_action": "Manual review",
                },
            ]
        )

        self.assertEqual(analytics["enriched_indicator_count"], 4)
        self.assertEqual(analytics["top_dangerous_indicators"][0]["indicator"], "danger.example")
        self.assertEqual(analytics["top_dangerous_indicators"][0]["malicious"], 3)
        self.assertEqual(analytics["highest_risk_by_ioc_type"][0]["ioc_type"], "domain")
        self.assertEqual(analytics["highest_risk_by_ioc_type"][0]["average_risk_score"], 90.0)
        risk_distribution = {
            row["label"]: row for row in analytics["risk_distribution"]
        }
        self.assertEqual(risk_distribution["High"]["count"], 1)
        self.assertEqual(risk_distribution["High"]["percentage"], 25.0)
        type_distribution = {
            row["label"]: row for row in analytics["ioc_type_distribution"]
        }
        self.assertEqual(type_distribution["url"]["count"], 2)
        self.assertEqual(type_distribution["url"]["percentage"], 50.0)
        action_distribution = {
            row["label"]: row for row in analytics["recommended_action_distribution"]
        }
        self.assertEqual(action_distribution["Block"]["count"], 1)
        self.assertEqual(action_distribution["Investigate"]["count"], 1)
        self.assertTrue(analytics["business_insights"])

    @patch("backend.gti_client._probe_json_endpoint")
    def test_fetch_ioc_stream_builds_filters(self, mock_probe) -> None:
        mock_probe.return_value = {
            "http_status": 200,
            "response_headers": {},
            "raw_json": {"data": []},
        }

        result = gti_client.fetch_ioc_stream(
            api_key="test-key",
            entity_type="domain",
            origin="hunting",
            descriptors_only=True,
            pages_to_fetch=2,
        )

        self.assertEqual(result["status_code"], 200)
        params = mock_probe.call_args.kwargs["params"]
        self.assertEqual(params["limit"], 40)
        self.assertEqual(params["filter"], "entity_type:domain origin:hunting")
        self.assertEqual(params["descriptors_only"], "true")
        self.assertEqual(params["order"], "date")
        self.assertEqual(result["request_params"]["pages_to_fetch"], 2)
        self.assertEqual(result["request_params"]["api_page_limit"], 40)
        self.assertNotIn("date", params.get("filter", ""))

    @patch("backend.gti_client._probe_json_endpoint")
    def test_fetch_ioc_stream_collects_all_returned_pages_without_date_filtering(
        self,
        mock_probe,
    ) -> None:
        def page(start: int, dates: list[str], next_cursor: str | None = None) -> dict:
            payload = {
                "data": [
                    {
                        "id": f"example-{index}.com",
                        "type": "domain",
                        "attributes": {"matched_date": matched_date},
                    }
                    for index, matched_date in enumerate(dates, start=start)
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
            page(0, ["2026-05-21T10:00:00Z", "2026-05-20T10:00:00Z"], "cursor-1"),
            page(40, ["2026-05-19T10:00:00Z", "2026-05-18T10:00:00Z"], "cursor-2"),
            page(80, ["2026-05-13T10:00:00Z"]),
        ]

        result = gti_client.fetch_ioc_stream(
            api_key="test-key",
            pages_to_fetch=5,
            time_window="custom",
            start_date="2026-05-14",
            end_date="2026-05-21",
        )

        self.assertEqual(mock_probe.call_count, 3)
        call_params = [call.kwargs["params"] for call in mock_probe.call_args_list]
        self.assertEqual(call_params[0]["limit"], 40)
        self.assertNotIn("cursor", call_params[0])
        self.assertEqual(call_params[1]["limit"], 40)
        self.assertEqual(call_params[1]["cursor"], "cursor-1")
        self.assertEqual(call_params[2]["limit"], 40)
        self.assertEqual(call_params[2]["cursor"], "cursor-2")
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["total_collected"], 5)
        self.assertEqual(len(result["raw_data"]["data"]), 5)
        self.assertEqual(result["collection"]["pages_fetched"], 3)
        self.assertEqual(result["collection"]["stopped_reason"], "no_more_pages")
        self.assertEqual(result["collection"]["earliest_timestamp"], "2026-05-13T10:00:00+00:00")

    @patch("backend.gti_client._probe_json_endpoint")
    def test_fetch_ioc_stream_follows_unquoted_link_header(self, mock_probe) -> None:
        mock_probe.side_effect = [
            {
                "http_status": 200,
                "response_headers": {
                    "Link": '<https://www.virustotal.com/api/v3/ioc_stream?cursor=next-page>; rel=next'
                },
                "raw_json": {
                    "data": [
                        {
                            "id": "first.example",
                            "type": "domain",
                            "attributes": {"matched_date": "2026-05-21T10:00:00Z"},
                        }
                    ]
                },
            },
            {
                "http_status": 200,
                "response_headers": {},
                "raw_json": {
                    "data": [
                        {
                            "id": "second.example",
                            "type": "domain",
                            "attributes": {"matched_date": "2026-05-20T10:00:00Z"},
                        }
                    ]
                },
            },
        ]

        result = gti_client.fetch_ioc_stream(
            api_key="test-key",
            pages_to_fetch=2,
        )

        self.assertEqual(mock_probe.call_count, 2)
        self.assertEqual(mock_probe.call_args_list[1].kwargs["params"]["cursor"], "next-page")
        self.assertEqual(result["total_collected"], 2)
        self.assertEqual(result["collection"]["pages_fetched"], 2)

    @patch("backend.gti_client._probe_json_endpoint")
    def test_fetch_ioc_stream_reports_sample_warning_without_next_page(
        self,
        mock_probe,
    ) -> None:
        mock_probe.return_value = {
            "http_status": 200,
            "response_headers": {},
            "raw_json": {
                "data": [
                    {
                        "id": "first.example",
                        "type": "domain",
                        "attributes": {"matched_date": "2026-05-21T10:00:00Z"},
                    }
                ]
            },
        }

        result = gti_client.fetch_ioc_stream(
            api_key="test-key",
            pages_to_fetch=10,
        )

        self.assertEqual(mock_probe.call_count, 1)
        self.assertEqual(result["collection"]["stopped_reason"], "no_more_pages")
        self.assertIn(
            "IoC Stream is chronological. This report summarizes the recent pages returned by the API, not a guaranteed complete time window.",
            result["warnings"],
        )
        page_diagnostics = result["page_diagnostics"]
        self.assertEqual(page_diagnostics[0]["raw_page_item_count"], 1)
        self.assertFalse(page_diagnostics[0]["next_cursor_found"])
        self.assertFalse(page_diagnostics[0]["next_link_found"])

    @patch("backend.gti_client._probe_json_endpoint")
    def test_fetch_ioc_stream_follows_relative_next_link_without_cursor(
        self,
        mock_probe,
    ) -> None:
        mock_probe.side_effect = [
            {
                "http_status": 200,
                "response_headers": {},
                "raw_json": {
                    "data": [
                        {
                            "id": "first.example",
                            "type": "domain",
                            "attributes": {"matched_date": "2026-05-21T10:00:00Z"},
                        }
                    ],
                    "links": {"next": "/api/v3/ioc_stream?page=2"},
                },
            },
            {
                "http_status": 200,
                "response_headers": {},
                "raw_json": {
                    "data": [
                        {
                            "id": "second.example",
                            "type": "domain",
                            "attributes": {"matched_date": "2026-05-20T10:00:00Z"},
                        }
                    ]
                },
            },
        ]

        result = gti_client.fetch_ioc_stream(
            api_key="test-key",
            pages_to_fetch=2,
        )

        self.assertEqual(mock_probe.call_count, 2)
        self.assertEqual(
            mock_probe.call_args_list[1].kwargs["url"],
            "https://www.virustotal.com/api/v3/ioc_stream?page=2",
        )
        self.assertIsNone(mock_probe.call_args_list[1].kwargs["params"])
        self.assertEqual(result["total_collected"], 2)
        self.assertEqual(result["collection"]["pages_fetched"], 2)

    @patch("backend.gti_client._probe_json_endpoint")
    def test_fetch_ioc_stream_uses_page_cursor_from_next_link(self, mock_probe) -> None:
        mock_probe.side_effect = [
            {
                "http_status": 200,
                "response_headers": {},
                "raw_json": {
                    "data": [
                        {
                            "id": "first.example",
                            "type": "domain",
                            "attributes": {"matched_date": "2026-05-21T10:00:00Z"},
                        }
                    ],
                    "links": {
                        "next": "https://www.virustotal.com/api/v3/ioc_stream?page%5Bcursor%5D=abc"
                    },
                },
            },
            {
                "http_status": 200,
                "response_headers": {},
                "raw_json": {
                    "data": [
                        {
                            "id": "second.example",
                            "type": "domain",
                            "attributes": {"matched_date": "2026-05-20T10:00:00Z"},
                        }
                    ]
                },
            },
        ]

        result = gti_client.fetch_ioc_stream(
            api_key="test-key",
            pages_to_fetch=2,
        )

        self.assertEqual(mock_probe.call_count, 2)
        self.assertEqual(mock_probe.call_args_list[1].kwargs["params"]["cursor"], "abc")
        self.assertEqual(result["total_collected"], 2)

    @patch("backend.gti_client._probe_json_endpoint")
    def test_fetch_ioc_stream_continues_to_requested_pages_when_timestamps_are_missing(
        self,
        mock_probe,
    ) -> None:
        def page(identifier: str, cursor: str | None = None) -> dict:
            payload = {"data": [{"id": identifier, "type": "url", "attributes": {}}]}
            if cursor:
                payload["meta"] = {"next_cursor": cursor}
            return {"http_status": 200, "response_headers": {}, "raw_json": payload}

        mock_probe.side_effect = [
            page("one", "cursor-1"),
            page("two", "cursor-2"),
        ]

        result = gti_client.fetch_ioc_stream(
            api_key="test-key",
            pages_to_fetch=2,
        )

        self.assertEqual(mock_probe.call_count, 2)
        self.assertEqual(result["total_collected"], 2)
        self.assertEqual(result["collection"]["stopped_reason"], "requested_pages_reached")
        self.assertIn("IoC Stream is chronological", " ".join(result["warnings"]))

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
    def test_build_ioc_stream_report_enriches_all_returned_by_default(self, mock_enrich) -> None:
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

        self.assertEqual(mock_enrich.call_count, 12)
        self.assertEqual(report["summary"]["total_iocs"], 12)
        self.assertEqual(report["summary"]["high_risk"], 12)
        self.assertEqual(report["summary"]["unknown_risk"], 0)
        self.assertEqual(report["technical_details"]["enrichment"]["attempted"], 12)
        self.assertEqual(report["technical_details"]["enrichment"]["succeeded"], 12)
        self.assertEqual(report["technical_details"]["enrichment"]["requested_limit"], 12)
        self.assertEqual(report["technical_details"]["enrichment"]["actual_limit"], 12)

    @patch("backend.gti_client.enrich_ioc_indicator")
    def test_build_ioc_stream_report_uses_requested_enrichment_limit(self, mock_enrich) -> None:
        def enrich_side_effect(api_key, indicator):
            updated = dict(indicator)
            updated["enrichment_status"] = "success"
            updated["malicious"] = 0
            updated["suspicious"] = 0
            updated["reputation"] = 1
            updated["severity"] = "Low"
            updated["risk"] = "Low"
            updated["recommended_action"] = "Monitor"
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
            enrichment_limit=5,
        )

        self.assertEqual(mock_enrich.call_count, 5)
        self.assertEqual(report["technical_details"]["enrichment"]["attempted"], 5)
        self.assertEqual(report["technical_details"]["enrichment"]["requested_limit"], 5)
        self.assertEqual(report["technical_details"]["enrichment"]["actual_limit"], 5)

    @patch("backend.gti_client.enrich_ioc_indicator")
    def test_build_ioc_stream_report_deduplicates_before_enrichment(self, mock_enrich) -> None:
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
            "collection": {"stopped_reason": "no_more_pages"},
            "raw_data": {
                "data": [
                    {"id": "duplicate.example", "type": "domain", "attributes": {}},
                    {"id": "duplicate.example", "type": "domain", "attributes": {}},
                    {"id": "unique.example", "type": "domain", "attributes": {}},
                ]
            },
        }

        report = gti_client.build_ioc_stream_report(
            stream_result,
            api_key="test-key",
            enrich=True,
        )

        self.assertEqual(mock_enrich.call_count, 2)
        self.assertEqual(report["summary"]["total_iocs"], 2)
        self.assertEqual(report["collection"]["unique_ioc_count"], 2)
        self.assertEqual(report["collection"]["duplicates_removed"], 1)
        self.assertEqual(
            report["technical_details"]["diagnostics"]["duplicate_count"],
            1,
        )
        self.assertEqual(
            [indicator["value"] for indicator in report["indicators"]],
            ["duplicate.example", "unique.example"],
        )

    def test_enriched_risk_context_without_detections_is_low_not_unknown(self) -> None:
        classification = gti_client.classify_enriched_ioc_risk(
            malicious=0,
            suspicious=0,
            reputation=None,
            fallback_risk="Unknown",
            has_risk_context=True,
        )

        self.assertEqual(classification["risk"], "Low")
        self.assertEqual(classification["recommended_action"], "Monitor")


if __name__ == "__main__":
    unittest.main()
