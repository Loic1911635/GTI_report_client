import unittest
from unittest.mock import patch

from backend import gti_client
from backend.top_ranking_docx import build_cross_analysis_matrices


class AggregateTopTargetsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ttp_patcher = patch(
            "backend.gti_client.analyze_top_ttps",
            return_value={
                "top_tactics": [],
                "top_techniques": [],
                "top_subtechniques": [],
                "ttp_lookups_attempted": 0,
                "ttp_lookups_succeeded": 0,
                "ttp_eligible_collections": 0,
                "ttp_first_successful_collection_id": None,
                "ttp_first_successful_debug": {},
                "ttp_lookup_attempt_samples": [],
            },
        )
        self.ttp_patcher.start()
        self.addCleanup(self.ttp_patcher.stop)

    def test_estimate_top_ranking_requests(self) -> None:
        estimate = gti_client.estimate_top_ranking_requests(
            max_collections=1000,
            deep_lookup=False,
            max_detail_lookups=0,
        )

        self.assertEqual(
            estimate,
            {
                "page_size": 40,
                "max_collections": 1000,
                "estimated_search_pages": 25,
                "search_requests": 25,
                "deep_lookup_enabled": False,
                "max_detail_lookups": 0,
                "detail_lookup_requests": 0,
                "estimated_total_requests": 25,
                "total_requests": 25,
            },
        )

    @patch("backend.gti_client.get_collection_details")
    @patch("backend.gti_client.intelligence_search")
    def test_default_uses_preview_fields_without_detail_lookups(
        self,
        mock_intelligence_search,
        mock_get_collection_details,
    ) -> None:
        mock_intelligence_search.return_value = {
            "status_code": 200,
            "next_cursor": None,
            "simplified_preview": [
                {
                    "id": "coll-1",
                    "name": "Collection One",
                    "collection_type": "industry-profile",
                    "targeted_industries": ["Finance", " finance ", "FINANCE"],
                    "targeted_organizations": ["Acme", " acme ", "ACME"],
                },
                {
                    "id": "coll-2",
                    "name": "Collection Two",
                    "collection_type": "threat-report",
                    "targeted_industries": ["Finance", "Retail"],
                    "targeted_organizations": [],
                },
                {
                    "id": "coll-1",
                    "name": "Collection One Duplicate",
                    "collection_type": "industry-profile",
                    "targeted_industries": ["Finance"],
                    "targeted_organizations": ["Acme"],
                },
            ],
            "raw_data": {"data": []},
        }
        mock_get_collection_details.return_value = {
            "status_code": 200,
            "analysis": {
                "targeted_organizations": ["Beta", " beta "],
                "aggregations": {
                    "organizations": [{"name": "Beta"}, {"name": "Acme"}],
                },
            },
            "raw_data": {"data": {}},
        }

        result = gti_client.aggregate_top_targets(
            api_key="test-key",
            start_year=2024,
            top_n=10,
            max_collections=40,
        )

        self.assertEqual(
            result["query_used"],
            "entity:collection creation_date:2024-01-01+ creation_date:2024-12-31-",
        )
        self.assertEqual(result["collections_analyzed"], 2)
        self.assertEqual(result["company_detail_lookups_attempted"], 0)
        self.assertEqual(result["company_detail_lookups_succeeded"], 0)

        industries = {
            item["name"]: item["collection_count"] for item in result["top_industries"]
        }
        companies = {
            item["name"]: item["collection_count"] for item in result["top_companies"]
        }

        self.assertEqual(industries["Finance"], 2)
        self.assertEqual(industries["Retail"], 1)
        self.assertEqual(companies["Acme"], 1)
        mock_get_collection_details.assert_not_called()

    @patch("backend.gti_client.get_collection_details")
    @patch("backend.gti_client.intelligence_search")
    def test_deep_lookup_uses_bounded_collection_details(
        self,
        mock_intelligence_search,
        mock_get_collection_details,
    ) -> None:
        mock_intelligence_search.return_value = {
            "status_code": 200,
            "next_cursor": None,
            "simplified_preview": [
                {
                    "id": "coll-1",
                    "name": "Collection One",
                    "collection_type": "industry-profile",
                    "targeted_industries": ["Finance"],
                    "targeted_organizations": [],
                },
                {
                    "id": "coll-2",
                    "name": "Collection Two",
                    "collection_type": "threat-report",
                    "targeted_industries": ["Retail"],
                    "targeted_organizations": [],
                },
            ],
            "raw_data": {"data": []},
        }
        mock_get_collection_details.return_value = {
            "status_code": 200,
            "analysis": {"targeted_organizations": ["Beta"]},
            "raw_data": {"data": {}},
        }

        result = gti_client.aggregate_top_targets(
            api_key="test-key",
            start_year=2024,
            top_n=10,
            max_collections=40,
            deep_organization_lookup=True,
            max_detail_lookups=1,
        )

        companies = {
            item["name"]: item["collection_count"] for item in result["top_companies"]
        }
        self.assertEqual(companies, {"Beta": 1})
        self.assertEqual(result["company_detail_lookups_attempted"], 1)
        self.assertEqual(result["company_detail_lookups_succeeded"], 1)
        mock_get_collection_details.assert_called_once_with("test-key", "coll-1")

    @patch("backend.gti_client.intelligence_search")
    def test_non_200_search_raises_explicit_error(
        self,
        mock_intelligence_search,
    ) -> None:
        mock_intelligence_search.return_value = {
            "status_code": 401,
            "next_cursor": None,
            "simplified_preview": [],
            "raw_data": {"error": {"message": "Invalid API key"}},
        }

        with self.assertRaisesRegex(
            gti_client.GTIClientError,
            "401.*Invalid API key",
        ):
            gti_client.aggregate_top_targets(
                api_key="bad-key",
                start_year=2024,
                max_collections=40,
            )

    @patch("backend.gti_client.get_collection_details")
    @patch("backend.gti_client.intelligence_search")
    def test_detail_lookup_failure_stays_conservative(
        self,
        mock_intelligence_search,
        mock_get_collection_details,
    ) -> None:
        mock_intelligence_search.return_value = {
            "status_code": 200,
            "next_cursor": None,
            "simplified_preview": [
                {
                    "id": "coll-1",
                    "name": "Collection One",
                    "collection_type": "industry-profile",
                    "targeted_industries": ["Finance"],
                    "targeted_organizations": ["Acme"],
                },
                {
                    "id": "coll-2",
                    "name": "Collection Two",
                    "collection_type": "threat-report",
                    "targeted_industries": ["Retail"],
                    "targeted_organizations": [],
                },
            ],
            "raw_data": {"data": []},
        }
        mock_get_collection_details.return_value = {
            "status_code": 503,
            "analysis": {},
            "raw_data": {"error": {"message": "Service unavailable"}},
        }

        result = gti_client.aggregate_top_targets(
            api_key="test-key",
            start_year=2024,
            top_n=10,
            max_collections=40,
            deep_organization_lookup=True,
            max_detail_lookups=1,
        )

        companies = {
            item["name"]: item["collection_count"] for item in result["top_companies"]
        }
        self.assertEqual(companies, {"Acme": 1})
        self.assertEqual(result["company_detail_lookups_attempted"], 1)
        self.assertEqual(result["company_detail_lookups_succeeded"], 0)

    @patch("backend.gti_client.get_collection_details")
    @patch("backend.gti_client.intelligence_search")
    def test_companies_status_is_not_enough_data_without_preview_orgs(
        self,
        mock_intelligence_search,
        mock_get_collection_details,
    ) -> None:
        mock_intelligence_search.return_value = {
            "status_code": 200,
            "next_cursor": None,
            "simplified_preview": [
                {
                    "id": "coll-1",
                    "name": "Collection One",
                    "collection_type": "industry-profile",
                    "targeted_industries": ["Finance"],
                    "targeted_organizations": [],
                    "targeted_regions": ["Europe"],
                    "source_regions": ["North America"],
                    "tags": ["ransomware"],
                },
            ],
            "raw_data": {"data": []},
        }

        result = gti_client.aggregate_top_targets(
            api_key="test-key",
            start_year=2024,
            max_collections=40,
        )

        self.assertEqual(result["top_companies"], [])
        self.assertEqual(result["top_companies_status"], "not enough data")
        self.assertEqual(result["collection_preview_fields"][0]["targeted_regions"], ["Europe"])
        self.assertEqual(result["collection_preview_fields"][0]["source_regions"], ["North America"])
        self.assertEqual(result["collection_preview_fields"][0]["tags"], ["ransomware"])
        mock_get_collection_details.assert_not_called()

    @patch("backend.gti_client.intelligence_search")
    def test_month_query_uses_first_and_last_day_without_range_syntax(
        self,
        mock_intelligence_search,
    ) -> None:
        mock_intelligence_search.return_value = {
            "status_code": 200,
            "next_cursor": None,
            "simplified_preview": [],
            "raw_data": {"data": []},
        }

        result = gti_client.aggregate_top_targets(
            api_key="test-key",
            start_year=2024,
            month=4,
            max_collections=1000,
            selected_rankings=["timeline"],
        )

        self.assertEqual(
            result["query_used"],
            "entity:collection creation_date:2024-04-01+ creation_date:2024-04-30-",
        )
        self.assertNotIn("..", result["query_used"])
        self.assertEqual(result["period"], "April 2024")

    @patch("backend.gti_client.intelligence_search")
    def test_selected_rankings_and_field_coverage_are_returned(
        self,
        mock_intelligence_search,
    ) -> None:
        mock_intelligence_search.return_value = {
            "status_code": 200,
            "next_cursor": None,
            "simplified_preview": [
                {
                    "id": "coll-1",
                    "name": "Collection One",
                    "collection_type": "report",
                    "creation_date": "2024-04-12",
                    "targeted_regions": ["Europe"],
                    "source_regions": ["North America"],
                    "tags": ["ransomware"],
                    "victims": ["Acme"],
                },
            ],
            "raw_data": {"data": []},
        }

        result = gti_client.aggregate_top_targets(
            api_key="test-key",
            start_year=2024,
            max_collections=1000,
            selected_rankings=[
                "targeted_regions",
                "source_regions",
                "tags",
                "collection_type",
                "timeline",
                "targeted_organizations",
            ],
        )

        self.assertEqual(result["fields_coverage"]["targeted_regions"], 1)
        self.assertEqual(result["fields_coverage"]["source_regions"], 1)
        self.assertEqual(result["fields_coverage"]["tags"], 1)
        self.assertEqual(result["fields_coverage"]["collection_type"], 1)
        self.assertEqual(result["fields_coverage"]["targeted_organizations"], 1)
        self.assertEqual(result["rankings"]["timeline"][0]["name"], "2024-04")
        self.assertEqual(result["rankings"]["targeted_organizations"][0]["name"], "Acme")

    @patch("backend.gti_client.intelligence_search")
    def test_aliases_nested_fields_timestamps_and_debug_are_extracted(
        self,
        mock_intelligence_search,
    ) -> None:
        mock_intelligence_search.return_value = {
            "status_code": 200,
            "next_cursor": None,
            "simplified_preview": [
                {
                    "id": "coll-1",
                    "name": "Collection One",
                    "attributes": {
                        "targeted_industries_free": ["Finance"],
                        "targeted_regions_hierarchy": [
                            {"name": "Europe", "children": [{"label": "France"}]},
                        ],
                        "source_region": {"value": "North America"},
                        "threat_categories": [{"title": "Ransomware"}],
                        "collection_subtype": "threat-report",
                        "companies": [{"name": "Acme"}],
                        "creation_date": "1715472000",
                    },
                },
            ],
            "raw_data": {"data": []},
        }

        result = gti_client.aggregate_top_targets(
            api_key="test-key",
            start_year=2024,
            max_collections=1000,
            selected_rankings=[
                "targeted_industries",
                "targeted_regions",
                "source_regions",
                "tags",
                "collection_type",
                "timeline",
                "targeted_organizations",
            ],
        )

        self.assertEqual(result["rankings"]["targeted_industries"][0]["name"], "Finance")
        self.assertEqual(result["rankings"]["targeted_regions"][0]["name"], "Europe")
        self.assertEqual(result["rankings"]["source_regions"][0]["name"], "North America")
        self.assertEqual(result["rankings"]["tags"][0]["name"], "Ransomware")
        self.assertEqual(result["rankings"]["collection_type"][0]["name"], "threat-report")
        self.assertEqual(result["rankings"]["timeline"][0]["name"], "2024-05")
        self.assertEqual(result["rankings"]["targeted_organizations"][0]["name"], "Acme")
        self.assertEqual(result["fields_coverage"]["timeline"], 1)
        self.assertEqual(
            result["debug_attribute_keys_frequency"]["targeted_regions_hierarchy"],
            1,
        )
        self.assertEqual(
            result["debug_sample_collection_fields"][0]["non_empty_ranking_fields"]["tags"],
            ["Ransomware"],
        )

    def test_simplify_intelligence_search_item_uses_preview_aliases(self) -> None:
        simplified = gti_client._simplify_intelligence_search_item(
            {
                "id": "coll-1",
                "type": "collection",
                "attributes": {
                    "collection_subtype": "industry-profile",
                    "targeted_industries_free": ["Finance"],
                    "targeted_region": ["Europe"],
                    "source_regions_hierarchy": [{"name": "North America"}],
                    "threat_category": ["Ransomware"],
                    "companies": ["Acme"],
                    "creation_date": "2024-05-12T10:11:12Z",
                },
            }
        )

        self.assertEqual(simplified["collection_type"], "industry-profile")
        self.assertEqual(simplified["targeted_industries"], ["Finance"])
        self.assertEqual(simplified["targeted_regions"], ["Europe"])
        self.assertEqual(simplified["source_regions"], [{"name": "North America"}])
        self.assertEqual(simplified["tags"], ["Ransomware"])
        self.assertEqual(simplified["targeted_organizations"], ["Acme"])
        self.assertIn("companies", simplified["attributes_keys"])

    def test_docx_cross_analysis_counts_pairs_once_per_collection(self) -> None:
        matrices = build_cross_analysis_matrices(
            [
                {
                    "targeted_industries": ["Finance", "Finance"],
                    "tags": ["ransomware", "ransomware"],
                    "collection_type": "report",
                    "targeted_regions": ["Europe"],
                    "source_regions": ["North America"],
                    "creation_date": "2024-05-12",
                },
                {
                    "targeted_industries": ["Finance"],
                    "tags": ["phishing"],
                    "collection_type": "report",
                    "targeted_regions": ["Europe"],
                    "source_regions": ["Asia"],
                    "creation_date": "2024-05-20",
                },
            ],
            top_rows=5,
            top_columns=5,
        )

        industry_tag = matrices["industries_by_tags"]
        self.assertEqual(industry_tag["eligible_collections"], 2)
        self.assertEqual(industry_tag["rows"][0]["label"], "Finance")
        self.assertIn("ransomware", industry_tag["columns"])
        ransomware_index = industry_tag["columns"].index("ransomware")
        self.assertEqual(industry_tag["rows"][0]["cells"][ransomware_index], 1)
        self.assertEqual(
            matrices["timeline_by_collection_type"]["rows"][0]["label"],
            "2024-05",
        )


class MitreTreeTtpTests(unittest.TestCase):
    def test_known_schema_parser_extracts_techniques_and_subtechniques(self) -> None:
        payload = {
            "data": {
                "tactics": [
                    {
                        "id": "TA0002",
                        "name": "Execution",
                        "techniques": [
                            {
                                "attack_id": "T1059",
                                "technique_name": "Command and Scripting Interpreter",
                                "subtechniques": [
                                    {
                                        "attack_id": "T1059.001",
                                        "name": "PowerShell",
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        }

        entries = gti_client._parse_mitre_tree_entries(payload)

        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["type"], "technique")
        self.assertEqual(entries[0]["tactic_name"], "Execution")
        self.assertEqual(entries[0]["technique_id"], "T1059")
        self.assertEqual(entries[1]["type"], "subtechnique")
        self.assertEqual(entries[1]["subtechnique_id"], "T1059.001")

    @patch("backend.gti_client._fetch_mitre_tree")
    def test_single_mitre_tree_returns_debug_shape(self, mock_fetch_mitre_tree) -> None:
        mock_fetch_mitre_tree.return_value = {
            "status_code": 200,
            "raw_data": {
                "data": {
                    "tactics": [
                        {
                            "id": "TA0002",
                            "name": "Execution",
                            "children": [
                                {"id": "T1059", "name": "Command and Scripting Interpreter"}
                            ],
                        }
                    ]
                }
            },
        }

        result = gti_client.test_single_mitre_tree("key", "collection-id")

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["top_level_keys"], ["data"])
        self.assertEqual(result["data_keys"], ["tactics"])
        self.assertEqual(result["tactics_count"], 1)
        self.assertEqual(result["parsed_entries_count"], 1)
        self.assertEqual(result["first_parsed_entries"][0]["technique_id"], "T1059")
        mock_fetch_mitre_tree.assert_called_once_with("key", "collection-id")

    @patch("backend.gti_client._fetch_mitre_tree")
    @patch("backend.gti_client.intelligence_search")
    def test_analyze_top_ttps_uses_dedicated_report_search(
        self,
        mock_intelligence_search,
        mock_fetch_mitre_tree,
    ) -> None:
        mock_intelligence_search.return_value = {
            "status_code": 200,
            "next_cursor": None,
            "simplified_preview": [{"id": "coll-1", "type": "collection"}],
            "raw_data": {"data": []},
        }
        mock_fetch_mitre_tree.return_value = {
            "status_code": 200,
            "raw_data": {
                "data": {
                    "tactics": [
                        {
                            "id": "TA0002",
                            "name": "Execution",
                            "techniques": [{"id": "T1059", "name": "Command"}],
                        }
                    ]
                }
            },
        }

        result = gti_client.analyze_top_ttps(
            api_key="key",
            date_filter="creation_date:2024-01-01+ creation_date:2024-12-31-",
            max_ttp_candidates=25,
        )

        query = mock_intelligence_search.call_args.kwargs["query"]
        self.assertIn("entity:collection collection_type:report", query)
        self.assertEqual(result["ttp_lookups_attempted"], 1)
        self.assertEqual(result["ttp_lookups_succeeded"], 1)
        self.assertEqual(result["ttp_first_successful_collection_id"], "coll-1")
        self.assertEqual(result["top_tactics"][0]["name"], "TA0002 - Execution")
        self.assertEqual(result["top_techniques"][0]["name"], "T1059 - Command")

    @patch("backend.gti_client._fetch_mitre_tree")
    def test_analyze_top_ttps_warns_when_parser_extracts_no_techniques(
        self,
        mock_fetch_mitre_tree,
    ) -> None:
        mock_fetch_mitre_tree.return_value = {
            "status_code": 200,
            "raw_data": {"data": {"tactics": [{"id": "TA0001", "name": "Initial Access"}]}},
        }

        result = gti_client.analyze_top_ttps(
            api_key="key",
            date_filter="creation_date:2024-01-01+ creation_date:2024-12-31-",
            source="ranking_collections",
            ranking_collections=[{"id": "coll-1"}],
        )

        self.assertEqual(
            result["warning_message"],
            "MITRE tree was returned by GTI, but parser failed to extract techniques.",
        )


if __name__ == "__main__":
    unittest.main()
