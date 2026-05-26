import unittest
import base64
import json
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
            max_pages=2,
        )

        self.assertEqual(result["status_code"], 200)
        params = mock_probe.call_args.kwargs["params"]
        self.assertEqual(params["limit"], 40)
        self.assertEqual(params["filter"], "entity_type:domain origin:hunting")
        self.assertEqual(params["descriptors_only"], "true")
        self.assertEqual(params["order"], "date")
        self.assertEqual(result["request_params"]["pages_to_fetch"], 2)
        self.assertEqual(result["request_params"]["max_pages"], 2)
        self.assertEqual(result["request_params"]["api_page_limit"], 40)
        self.assertEqual(result["collection"]["page_size"], 40)
        self.assertNotIn("date", params.get("filter", ""))

    @patch("backend.gti_client._probe_json_endpoint")
    def test_fetch_ioc_stream_time_window_sends_server_side_date_filter(
        self,
        mock_probe,
    ) -> None:
        mock_probe.return_value = {
            "http_status": 200,
            "response_headers": {},
            "raw_json": {
                "data": [
                    {
                        "id": "https://example.test/path",
                        "type": "url",
                        "attributes": {"matched_on": "2026-05-20T10:00:00Z"},
                    }
                ]
            },
        }

        result = gti_client.fetch_ioc_stream(
            api_key="test-key",
            collection_mode="time_window",
            time_window="custom",
            start_date="2026-05-19",
            end_date="2026-05-25",
            entity_type="url",
            origin="hunting",
            max_pages=1,
        )

        params = mock_probe.call_args.kwargs["params"]
        self.assertEqual(params["limit"], 40)
        self.assertEqual(params["order"], "date")
        self.assertEqual(
            params["filter"],
            "date:2026-05-19+ date:2026-05-25- entity_type:url origin:hunting",
        )
        self.assertTrue(result["request_params"]["use_server_side_date_filter"])
        self.assertTrue(result["collection"]["server_side_date_filter_attempted"])
        self.assertEqual(
            result["collection"]["server_side_date_filter_string"],
            "date:2026-05-19+ date:2026-05-25-",
        )
        self.assertEqual(
            result["collection"]["server_side_date_filter_status"],
            "success",
        )
        self.assertEqual(result["collection"]["server_side_date_filter_item_count"], 1)
        self.assertEqual(
            result["collection"]["server_side_date_filter_returned_count"],
            1,
        )
        self.assertEqual(result["collection"]["local_inside_window_count"], 1)
        self.assertEqual(result["collection"]["local_outside_window_count"], 0)
        self.assertFalse(result["collection"]["fallback_used"])
        self.assertEqual(
            result["collection"]["coverage_status"],
            "server_filtered_sample",
        )

    @patch("backend.gti_client._probe_json_endpoint")
    def test_fetch_ioc_stream_time_window_revalidates_server_filtered_results(
        self,
        mock_probe,
    ) -> None:
        mock_probe.return_value = {
            "http_status": 200,
            "response_headers": {},
            "raw_json": {
                "data": [
                    {
                        "id": "inside.example",
                        "type": "domain",
                        "attributes": {"matched_on": "2026-05-20T10:00:00Z"},
                    },
                    {
                        "id": "old.example",
                        "type": "domain",
                        "attributes": {"matched_on": "2025-12-07T10:00:00Z"},
                    },
                ]
            },
        }

        result = gti_client.fetch_ioc_stream(
            api_key="test-key",
            collection_mode="time_window",
            time_window="custom",
            start_date="2026-05-19",
            end_date="2026-05-25",
            max_pages=1,
        )

        self.assertEqual(result["collection"]["coverage_status"], "server_filter_unverified")
        self.assertEqual(result["collection"]["server_side_date_filter_returned_count"], 2)
        self.assertEqual(result["collection"]["local_inside_window_count"], 1)
        self.assertEqual(result["collection"]["local_outside_window_count"], 1)
        self.assertEqual(result["collection"]["iocs_inside_window"], 1)
        self.assertEqual(
            result["collection"]["earliest_outside_window_timestamp"],
            "2025-12-07T10:00:00+00:00",
        )
        self.assertEqual(
            [item["id"] for item in result["raw_data"]["data"]],
            ["inside.example"],
        )
        self.assertIn(
            "GTI returned items outside the requested date window; local validation was applied.",
            result["warnings"],
        )

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
    def test_fetch_ioc_stream_time_window_falls_back_to_local_filtering(
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
            return {"http_status": 200, "response_headers": {}, "raw_json": payload}

        mock_probe.side_effect = [
            {"http_status": 400, "response_headers": {}, "raw_json": {"error": {}}},
            page(0, ["2026-05-21T10:00:00Z", "2026-05-20T10:00:00Z"], "cursor-1"),
            page(40, ["2026-05-19T10:00:00Z", "2026-05-18T10:00:00Z"], "cursor-2"),
            page(80, ["2026-05-13T10:00:00Z"]),
        ]

        result = gti_client.fetch_ioc_stream(
            api_key="test-key",
            collection_mode="time_window",
            time_window="custom",
            start_date="2026-05-14",
            end_date="2026-05-21",
            max_pages=5,
        )

        self.assertEqual(mock_probe.call_count, 4)
        first_params = mock_probe.call_args_list[0].kwargs["params"]
        self.assertEqual(first_params["filter"], "date:2026-05-14+ date:2026-05-21-")
        self.assertNotIn("filter", mock_probe.call_args_list[1].kwargs["params"])
        self.assertEqual(result["total_collected"], 4)
        self.assertEqual(len(result["raw_data"]["data"]), 4)
        self.assertEqual(result["collection"]["raw_ioc_count"], 5)
        self.assertEqual(result["collection"]["iocs_inside_window"], 4)
        self.assertEqual(result["collection"]["iocs_inside_selected_window"], 4)
        self.assertEqual(result["collection"]["coverage_status"], "no_more_pages")
        self.assertEqual(result["collection"]["stopped_reason"], "no_more_pages")
        self.assertTrue(result["collection"]["server_side_date_filter_attempted"])
        self.assertEqual(
            result["collection"]["server_side_date_filter_status"],
            "http_400",
        )
        self.assertTrue(result["collection"]["fallback_used"])
        self.assertIn(
            "Server-side date filter did not return usable results; fallback local filtering was used.",
            result["warnings"],
        )
        self.assertEqual(
            result["collection"]["earliest_fetched_timestamp"],
            "2026-05-13T10:00:00+00:00",
        )
        self.assertEqual(
            result["collection"]["earliest_kept_timestamp"],
            "2026-05-18T10:00:00+00:00",
        )

    @patch("backend.gti_client._probe_json_endpoint")
    def test_fetch_ioc_stream_time_window_falls_back_when_server_filter_is_empty(
        self,
        mock_probe,
    ) -> None:
        mock_probe.side_effect = [
            {"http_status": 200, "response_headers": {}, "raw_json": {"data": []}},
            {
                "http_status": 200,
                "response_headers": {},
                "raw_json": {
                    "data": [
                        {
                            "id": "inside.example",
                            "type": "domain",
                            "attributes": {"matched_on": "2026-05-20T10:00:00Z"},
                        }
                    ]
                },
            },
        ]

        result = gti_client.fetch_ioc_stream(
            api_key="test-key",
            collection_mode="time_window",
            time_window="custom",
            start_date="2026-05-19",
            end_date="2026-05-25",
            max_pages=1,
        )

        self.assertEqual(mock_probe.call_count, 2)
        self.assertEqual(
            result["collection"]["server_side_date_filter_status"],
            "empty",
        )
        self.assertTrue(result["collection"]["fallback_used"])
        self.assertEqual(result["total_collected"], 1)
        self.assertEqual(result["collection"]["coverage_status"], "no_more_pages")
        self.assertIn(
            "Server-side date filter did not return usable results; fallback local filtering was used.",
            result["warnings"],
        )

    @patch("backend.gti_client._probe_json_endpoint")
    def test_fetch_ioc_stream_time_window_marks_sample_when_requested_pages_reached(
        self,
        mock_probe,
    ) -> None:
        def page(identifier: str, matched_date: str, cursor: str | None = None) -> dict:
            payload = {
                "data": [
                    {
                        "id": identifier,
                        "type": "domain",
                        "attributes": {"matched_date": matched_date},
                    }
                ]
            }
            if cursor:
                payload["meta"] = {"next_cursor": cursor}
            return {"http_status": 200, "response_headers": {}, "raw_json": payload}

        mock_probe.side_effect = [
            page("one.example", "2026-05-21T10:00:00Z", "cursor-1"),
            page("two.example", "2026-05-20T10:00:00Z", "cursor-2"),
        ]

        result = gti_client.fetch_ioc_stream(
            api_key="test-key",
            collection_mode="time_window",
            time_window="custom",
            start_date="2026-05-14",
            end_date="2026-05-21",
            max_pages=2,
        )

        self.assertEqual(result["collection"]["stopped_reason"], "requested_pages_reached")
        self.assertEqual(result["collection"]["coverage_status"], "server_filtered_sample")
        self.assertEqual(
            result["collection"]["server_side_date_filter_status"],
            "success",
        )
        self.assertEqual(result["collection"]["raw_ioc_count"], 2)
        self.assertEqual(result["collection"]["iocs_inside_window"], 2)
        self.assertEqual(result["collection"]["iocs_inside_selected_window"], 2)

    @patch("backend.gti_client._probe_json_endpoint")
    def test_fetch_ioc_stream_time_window_does_not_stop_on_old_first_page_match(
        self,
        mock_probe,
    ) -> None:
        mock_probe.side_effect = [
            {"http_status": 404, "response_headers": {}, "raw_json": {"error": {}}},
            {
                "http_status": 200,
                "response_headers": {},
                "raw_json": {
                    "data": [
                        {
                            "id": "old-first-page.example",
                            "type": "domain",
                            "attributes": {"matched_on": "2026-05-13T10:00:00Z"},
                        },
                        {
                            "id": "inside-first-page.example",
                            "type": "domain",
                            "attributes": {"matched_on": "2026-05-20T10:00:00Z"},
                        },
                    ],
                    "meta": {"next_cursor": "cursor-1"},
                },
            },
            {
                "http_status": 200,
                "response_headers": {},
                "raw_json": {
                    "data": [
                        {
                            "id": "inside-second-page.example",
                            "type": "domain",
                            "attributes": {"matched_on": "2026-05-19T10:00:00Z"},
                        }
                    ],
                    "meta": {"next_cursor": "cursor-2"},
                },
            },
        ]

        result = gti_client.fetch_ioc_stream(
            api_key="test-key",
            collection_mode="time_window",
            time_window="custom",
            start_date="2026-05-14",
            end_date="2026-05-21",
            max_pages=2,
        )

        self.assertEqual(mock_probe.call_count, 3)
        self.assertEqual(result["collection"]["pages_fetched"], 2)
        self.assertEqual(result["collection"]["stopped_reason"], "requested_pages_reached")
        self.assertEqual(result["collection"]["coverage_status"], "sample_filtered")
        self.assertEqual(
            result["collection"]["server_side_date_filter_status"],
            "http_404",
        )
        self.assertTrue(result["collection"]["fallback_used"])
        self.assertEqual(result["collection"]["raw_iocs_fetched"], 3)
        self.assertEqual(result["collection"]["items_with_stream_timestamp"], 3)
        self.assertEqual(result["collection"]["items_without_stream_timestamp"], 0)
        self.assertEqual(result["collection"]["iocs_inside_selected_window"], 2)
        self.assertEqual(result["total_collected"], 2)

    @patch("backend.gti_client._probe_json_endpoint")
    def test_fetch_ioc_stream_time_window_marks_no_more_pages_before_start(
        self,
        mock_probe,
    ) -> None:
        mock_probe.return_value = {
            "http_status": 200,
            "response_headers": {},
            "raw_json": {
                "data": [
                    {
                        "id": "one.example",
                        "type": "domain",
                        "attributes": {"matched_date": "2026-05-21T10:00:00Z"},
                    }
                ]
            },
        }

        result = gti_client.fetch_ioc_stream(
            api_key="test-key",
            collection_mode="time_window",
            time_window="custom",
            start_date="2026-05-14",
            end_date="2026-05-21",
            max_pages=5,
        )

        self.assertEqual(result["collection"]["stopped_reason"], "no_more_pages")
        self.assertEqual(result["collection"]["coverage_status"], "server_filtered_sample")
        self.assertEqual(
            result["collection"]["server_side_date_filter_status"],
            "success",
        )

    @patch("backend.gti_client._probe_json_endpoint")
    def test_fetch_ioc_stream_time_window_ignores_old_object_metadata_for_stop(
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
                            "id": "one.example",
                            "type": "domain",
                            "attributes": {
                                "matched_date": "2026-05-21T10:00:00Z",
                                "creation_date": "2001-01-01T00:00:00Z",
                            },
                        }
                    ],
                    "meta": {"next_cursor": "cursor-1"},
                },
            },
            {
                "http_status": 200,
                "response_headers": {},
                "raw_json": {
                    "data": [
                        {
                            "id": "two.example",
                            "type": "domain",
                            "attributes": {
                                "matched_date": "2026-05-20T10:00:00Z",
                                "first_seen": "2004-01-01T00:00:00Z",
                            },
                        }
                    ]
                },
            },
        ]

        result = gti_client.fetch_ioc_stream(
            api_key="test-key",
            collection_mode="time_window",
            time_window="custom",
            start_date="2026-05-14",
            end_date="2026-05-21",
            max_pages=5,
        )

        self.assertEqual(mock_probe.call_count, 2)
        self.assertEqual(result["collection"]["stopped_reason"], "no_more_pages")
        self.assertEqual(result["collection"]["coverage_status"], "server_filtered_sample")
        self.assertEqual(result["collection"]["raw_ioc_count"], 2)
        self.assertEqual(result["collection"]["iocs_inside_window"], 2)
        self.assertEqual(
            result["collection"]["oldest_stream_event_timestamp"],
            "2026-05-20T10:00:00+00:00",
        )
        self.assertEqual(
            result["collection"]["oldest_object_metadata_timestamp"],
            "2001-01-01T00:00:00+00:00",
        )
        self.assertEqual(
            result["collection"]["ignored_object_metadata_old_timestamp_count"],
            2,
        )
        self.assertEqual(result["collection"]["items_with_stream_timestamp"], 2)
        self.assertEqual(result["collection"]["items_without_stream_timestamp"], 0)
        self.assertEqual(result["collection"]["stream_timestamp_fields_seen"], ["matched_date"])
        self.assertEqual(
            result["collection"]["object_metadata_timestamp_fields_seen"],
            ["creation_date", "first_seen"],
        )
        self.assertEqual(result["collection"]["stop_timestamp_field"], None)
        self.assertIn("matched_date", result["collection"]["timestamp_fields_seen"])
        self.assertIn("creation_date", result["collection"]["timestamp_fields_seen"])
        self.assertIn("first_seen", result["collection"]["timestamp_fields_seen"])

    @patch("backend.gti_client._probe_json_endpoint")
    def test_fetch_ioc_stream_time_window_uses_recursive_matched_on_fields(
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
                            "id": "inside.example",
                            "type": "domain",
                            "attributes": {
                                "gti_ui": {
                                    "matched_on": "2026-05-20T10:00:00Z",
                                },
                                "last_seen_itw_date": "2001-01-01T00:00:00Z",
                            },
                        }
                    ],
                    "meta": {"next_cursor": "cursor-1"},
                },
            },
            {
                "http_status": 200,
                "response_headers": {},
                "raw_json": {
                    "data": [
                        {
                            "id": "before-window.example",
                            "type": "domain",
                            "attributes": {
                                "details": {
                                    "matched_at": "2026-05-13T10:00:00Z",
                                }
                            },
                        }
                    ],
                },
            },
        ]

        result = gti_client.fetch_ioc_stream(
            api_key="test-key",
            collection_mode="time_window",
            time_window="custom",
            start_date="2026-05-14",
            end_date="2026-05-21",
            max_pages=5,
        )

        self.assertEqual(mock_probe.call_count, 2)
        self.assertEqual(result["collection"]["stopped_reason"], "no_more_pages")
        self.assertEqual(result["collection"]["coverage_status"], "server_filter_unverified")
        self.assertEqual(result["collection"]["raw_ioc_count"], 2)
        self.assertEqual(result["collection"]["local_inside_window_count"], 1)
        self.assertEqual(result["collection"]["local_outside_window_count"], 1)
        self.assertEqual(
            result["collection"]["earliest_outside_window_timestamp"],
            "2026-05-13T10:00:00+00:00",
        )
        self.assertEqual(result["total_collected"], 1)
        self.assertEqual(result["raw_data"]["data"][0]["id"], "inside.example")
        self.assertIn(
            "GTI returned items outside the requested date window; local validation was applied.",
            result["warnings"],
        )
        self.assertEqual(
            result["collection"]["earliest_fetched_timestamp"],
            "2026-05-13T10:00:00+00:00",
        )
        self.assertEqual(
            result["collection"]["latest_fetched_timestamp"],
            "2026-05-20T10:00:00+00:00",
        )
        self.assertEqual(
            result["collection"]["stream_timestamp_fields_seen"],
            ["matched_at", "matched_on"],
        )
        self.assertEqual(
            result["collection"]["object_metadata_timestamp_fields_seen"],
            ["last_seen_itw_date"],
        )

        raw_diagnostics = result["collection"]["raw_item_timestamp_diagnostics"]
        self.assertEqual(len(raw_diagnostics), 2)
        first_fields = {
            row["path"]: row
            for row in raw_diagnostics[0]["date_fields"]
        }
        self.assertTrue(
            first_fields["attributes.gti_ui.matched_on"][
                "accepted_as_stream_timestamp"
            ]
        )
        self.assertTrue(
            first_fields["attributes.last_seen_itw_date"][
                "rejected_as_object_metadata"
            ]
        )

    @patch("backend.gti_client._probe_json_endpoint")
    def test_fetch_ioc_stream_time_window_without_stream_timestamps_is_unavailable(
        self,
        mock_probe,
    ) -> None:
        mock_probe.return_value = {
            "http_status": 200,
            "response_headers": {},
            "raw_json": {
                "data": [
                    {
                        "id": "old-object.example",
                        "type": "domain",
                        "attributes": {
                            "creation_date": "2001-01-01T00:00:00Z",
                            "first_submission_date": "2004-01-01T00:00:00Z",
                            "last_seen_itw_date": "2005-01-01T00:00:00Z",
                            "engine_update": "2026-05-20T10:00:00Z",
                            "timeout": "30",
                            "confirmed-timeout": "60",
                            "processing_timestamp": "1777777777",
                        },
                    }
                ]
            },
        }

        result = gti_client.fetch_ioc_stream(
            api_key="test-key",
            collection_mode="time_window",
            time_window="custom",
            start_date="2026-05-14",
            end_date="2026-05-21",
            max_pages=5,
        )

        self.assertEqual(result["collection"]["stopped_reason"], "no_more_pages")
        self.assertEqual(result["collection"]["coverage_status"], "unavailable")
        self.assertEqual(result["collection"]["raw_ioc_count"], 1)
        self.assertEqual(result["collection"]["local_inside_window_count"], 0)
        self.assertEqual(result["collection"]["local_outside_window_count"], 0)
        self.assertEqual(result["total_collected"], 1)
        self.assertEqual(len(result["raw_data"]["data"]), 1)
        self.assertTrue(result["collection"]["time_window_filtering_applied"])
        self.assertIsNone(result["collection"]["recommendation"])
        self.assertEqual(result["collection"]["items_with_stream_timestamp"], 0)
        self.assertEqual(result["collection"]["items_without_stream_timestamp"], 1)
        self.assertEqual(result["collection"]["items_without_stream_timestamp_count"], 1)
        self.assertEqual(result["collection"]["stream_timestamp_fields_seen"], [])
        self.assertEqual(
            result["collection"]["object_metadata_timestamp_fields_seen"],
            ["creation_date", "first_submission_date", "last_seen_itw_date"],
        )
        self.assertEqual(
            result["collection"]["oldest_object_metadata_timestamp"],
            "2001-01-01T00:00:00+00:00",
        )
        raw_fields = {
            row["field"]
            for row in result["collection"]["raw_item_timestamp_diagnostics"][0][
                "date_fields"
            ]
        }
        self.assertNotIn("engine_update", raw_fields)
        self.assertNotIn("timeout", raw_fields)
        self.assertNotIn("confirmed_timeout", raw_fields)
        self.assertNotIn("processing_timestamp", raw_fields)
        self.assertNotIn(
            "GTI returned IoCs, but no usable stream notification timestamps were exposed. Time-window filtering could not be applied safely.",
            result["warnings"],
        )
        self.assertIn(
            "GTI did not expose usable stream timestamps, so date coverage cannot be verified.",
            result["warnings"],
        )

    def test_stream_event_datetime_keeps_object_created_at_separate(self) -> None:
        object_item = {
            "id": "object-created.example",
            "type": "domain",
            "attributes": {"created_at": "2001-01-01T00:00:00Z"},
        }
        notification_item = {
            "id": "stream-created.example",
            "type": "ioc_stream_notification",
            "attributes": {"created_at": "2026-05-21T10:00:00Z"},
        }

        self.assertIsNone(gti_client.extract_stream_event_datetime(object_item))
        self.assertEqual(
            gti_client.extract_object_metadata_datetime(object_item).isoformat(),
            "2001-01-01T00:00:00+00:00",
        )
        self.assertEqual(
            gti_client.extract_stream_event_datetime(notification_item).isoformat(),
            "2026-05-21T10:00:00+00:00",
        )

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
    def test_fetch_ioc_stream_ignores_full_http_next_cursor_candidate_until_valid_ioc_stream_page(self, mock_probe) -> None:
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
                    "meta": {
                        "next": "http://megaplaylive.com/?enc=" + "A" * 1000
                    },
                    "links": {
                        "next": "https://www.virustotal.com/api/v3/ioc_stream?cursor=real-cursor"
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
        self.assertEqual(mock_probe.call_args_list[1].kwargs["params"]["cursor"], "real-cursor")
        self.assertEqual(result["total_collected"], 2)
        self.assertEqual(result["collection"]["pages_fetched"], 2)
        self.assertEqual(result["page_diagnostics"][0]["next_cursor_source"], "payload.links.next")
        self.assertIsNotNone(result["page_diagnostics"][0]["ignored_cursor_reason"])
        self.assertTrue(result["page_diagnostics"][0]["ignored_cursor_candidate"].startswith("http://megaplaylive.com/"))

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

    def test_build_ioc_stream_report_exposes_sample_collection_metrics(self) -> None:
        stream_result = {
            "status_code": 200,
            "collection": {
                "requested_pages": 5,
                "pages_fetched": 2,
                "page_size": 40,
                "raw_ioc_count": 3,
                "stopped_reason": "no_more_pages",
                "earliest_timestamp": "2026-05-20T10:00:00+00:00",
                "latest_timestamp": "2026-05-21T10:00:00+00:00",
            },
            "raw_data": {
                "data": [
                    {"id": "duplicate.example", "type": "domain", "attributes": {}},
                    {"id": "duplicate.example", "type": "domain", "attributes": {}},
                    {"id": "unique.example", "type": "domain", "attributes": {}},
                ]
            },
        }

        report = gti_client.build_ioc_stream_report(stream_result)

        self.assertEqual(report["collection"]["requested_pages"], 5)
        self.assertEqual(report["collection"]["pages_fetched"], 2)
        self.assertEqual(report["collection"]["page_size"], 40)
        self.assertEqual(report["collection"]["raw_ioc_count"], 3)
        self.assertEqual(report["collection"]["unique_ioc_count"], 2)
        self.assertEqual(report["collection"]["duplicates_removed"], 1)
        self.assertEqual(report["collection"]["stopped_reason"], "no_more_pages")
        self.assertEqual(
            report["collection"]["earliest_timestamp"],
            "2026-05-20T10:00:00+00:00",
        )
        self.assertEqual(
            report["collection"]["latest_timestamp"],
            "2026-05-21T10:00:00+00:00",
        )

    def test_build_ioc_stream_report_handles_very_long_url_indicator(self) -> None:
        long_url = "https://example.test/" + "a" * 1200
        stream_result = {
            "status_code": 200,
            "raw_data": {
                "data": [
                    {
                        "id": long_url,
                        "type": "url",
                        "attributes": {
                            "matched_date": "2026-05-21T10:00:00Z",
                            "gti_score": 85,
                        },
                    },
                    {
                        "id": long_url,
                        "type": "url",
                        "attributes": {
                            "matched_date": "2026-05-21T10:00:00Z",
                            "gti_score": 85,
                        },
                    },
                ]
            },
        }

        report = gti_client.build_ioc_stream_report(stream_result)
        json.dumps(report)

        self.assertEqual(report["summary"]["total_iocs"], 1)
        self.assertEqual(report["collection"]["duplicates_removed"], 1)
        indicator = report["indicators"][0]
        self.assertEqual(indicator["value"], long_url)
        self.assertEqual(len(indicator["display_value"]), 120)
        self.assertTrue(indicator["display_value"].endswith("..."))
        self.assertEqual(
            indicator["ioc_key"],
            gti_client.stable_ioc_key("url", long_url),
        )
        self.assertEqual(len(indicator["ioc_key"]), 64)
        self.assertNotIn(long_url, report["charts"]["by_entity_type"][0].values())

    @patch("backend.gti_client._probe_json_endpoint")
    def test_enrich_ioc_indicator_keeps_long_url_when_lookup_errors(
        self,
        mock_probe,
    ) -> None:
        long_url = "https://example.test/" + "b" * 1200
        indicator = {
            "ioc_key": gti_client.stable_ioc_key("url", long_url),
            "value": long_url,
            "display_value": gti_client._truncate_ioc_display_value(long_url),
            "entity_type": "url",
            "severity": "Unknown",
            "recommended_action": "Manual review",
        }

        enriched = gti_client.enrich_ioc_indicator("test-key", indicator)

        mock_probe.assert_not_called()
        self.assertEqual(enriched["value"], long_url)
        self.assertEqual(enriched["enrichment_status"], "skipped")
        self.assertEqual(enriched["enrichment_skip_reason"], "url_too_long")
        self.assertIn("URL too long", enriched["enrichment_error"])

    @patch("backend.gti_client._probe_json_endpoint")
    def test_build_ioc_stream_report_skips_very_long_url_enrichment(
        self,
        mock_probe,
    ) -> None:
        long_url = "https://example.test/" + "c" * 1200
        stream_result = {
            "status_code": 200,
            "raw_data": {
                "data": [
                    {
                        "id": long_url,
                        "type": "url",
                        "attributes": {"matched_date": "2026-05-21T10:00:00Z"},
                    }
                ]
            },
        }

        report = gti_client.build_ioc_stream_report(
            stream_result,
            api_key="test-key",
            enrich=True,
        )

        mock_probe.assert_not_called()
        indicator = report["indicators"][0]
        self.assertEqual(indicator["value"], long_url)
        self.assertEqual(indicator["enrichment_status"], "skipped")
        self.assertIn("URL too long", indicator["enrichment_error"])
        self.assertEqual(report["summary"]["total_iocs"], 1)
        self.assertEqual(report["technical_details"]["enrichment"]["attempted"], 1)
        self.assertEqual(report["technical_details"]["enrichment"]["succeeded"], 0)
        self.assertEqual(report["technical_details"]["enrichment"]["errors"], 0)
        self.assertEqual(report["technical_details"]["enrichment"]["skipped"], 1)
        self.assertEqual(
            report["technical_details"]["enrichment"]["skipped_too_long_url"],
            1,
        )

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
