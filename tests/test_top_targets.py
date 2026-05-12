import unittest
from unittest.mock import patch

from backend import gti_client


class AggregateTopTargetsTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
