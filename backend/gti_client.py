"""Mock GTI client used by the MVP backend.

This module deliberately returns hard-coded sample data so the rest of the
application can be built and tested before a real Google Threat Intelligence
integration exists.
"""

from __future__ import annotations

from typing import Any


class MockGTIClient:
    """Very small mock client that imitates a future GTI integration."""

    def __init__(self, api_key: str) -> None:
        # We keep the API key because the real client will need it later.
        # In this MVP, we do not validate or send it anywhere.
        self.api_key = api_key

    def fetch_threat_landscape(
        self,
        report_type: str,
        year: int,
        target: str | None = None,
    ) -> dict[str, Any]:
        """Return sample GTI-like data for report generation.

        The returned structure is intentionally predictable so the report
        generator can work with a stable payload during early development.
        """

        # The target is optional in the API request, so we provide a friendly
        # fallback label to keep the report content readable.
        scoped_target = target or "Global threat landscape"

        return {
            "metadata": {
                "source": "mock_gti_client",
                "report_type": report_type,
                "year": year,
                "target": scoped_target,
                "notes": (
                    "This is sample data for the internship MVP. "
                    "Replace this client with a real GTI integration later."
                ),
            },
            "industries": [
                "Financial Services",
                "Healthcare",
                "Technology",
                "Manufacturing",
            ],
            "affected_companies": [
                {
                    "name": "Northbridge Bank",
                    "industry": "Financial Services",
                    "summary": "Credential theft campaign linked to phishing portals.",
                },
                {
                    "name": "MediCore Labs",
                    "industry": "Healthcare",
                    "summary": "Ransomware intrusion caused temporary lab system outages.",
                },
                {
                    "name": "Vertex Dynamics",
                    "industry": "Technology",
                    "summary": "Cloud identity abuse exposed internal development assets.",
                },
            ],
            "threat_actors": [
                {
                    "name": "UNC3944",
                    "motivation": "Financial gain",
                    "activity": "Social engineering and credential compromise.",
                },
                {
                    "name": "FIN7",
                    "motivation": "Financial gain",
                    "activity": "Targeting enterprise environments for malware delivery.",
                },
                {
                    "name": "APT29",
                    "motivation": "Espionage",
                    "activity": "Stealthy persistence and collection against strategic targets.",
                },
            ],
            "iocs": [
                {
                    "type": "domain",
                    "value": "secure-employee-portal[.]com",
                    "context": "Phishing infrastructure",
                },
                {
                    "type": "hash",
                    "value": "44d88612fea8a8f36de82e1278abb02f",
                    "context": "Known malware sample",
                },
                {
                    "type": "ip",
                    "value": "185.220.101.45",
                    "context": "Suspicious command-and-control node",
                },
            ],
        }
