import unittest
from unittest.mock import patch

from backend import gti_client


class AggregateTopTargetsTests(unittest.TestCase):
    @patch("backend.gti_client.get_collection_details")
    @patch("backend.gti_client.intelligence_search")
    def test_single_year_query_is_exact_and_counts_once_per_collection(
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
            max_pages=1,
        )

        self.assertEqual(
            result["query_used"],
            "entity:collection creation_date:2024-01-01+..2024-12-31+",
        )
        self.assertEqual(result["collections_analyzed"], 2)
        self.assertEqual(result["company_detail_lookups_attempted"], 1)
        self.assertEqual(result["company_detail_lookups_succeeded"], 1)

        industries = {
            item["name"]: item["collection_count"] for item in result["top_industries"]
        }
        companies = {
            item["name"]: item["collection_count"] for item in result["top_companies"]
        }

        self.assertEqual(industries["Finance"], 2)
        self.assertEqual(industries["Retail"], 1)
        self.assertEqual(companies["Acme"], 2)
        self.assertEqual(companies["Beta"], 1)
        mock_get_collection_details.assert_called_once_with("test-key", "coll-2")

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
                max_pages=1,
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
            max_pages=1,
        )

        companies = {
            item["name"]: item["collection_count"] for item in result["top_companies"]
        }
        self.assertEqual(companies, {"Acme": 1})
        self.assertEqual(result["company_detail_lookups_attempted"], 1)
        self.assertEqual(result["company_detail_lookups_succeeded"], 0)


if __name__ == "__main__":
    unittest.main()
