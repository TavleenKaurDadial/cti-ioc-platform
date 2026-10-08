from app.services.ioc_parser import identify_ioc


def correlate(enrichment: dict) -> dict:
    related_indicators = []
    indicator_groups = (
        ("related_ips", enrichment.get("related_ips", [])),
        ("related_domains", enrichment.get("related_domains", [])),
        ("related_urls", enrichment.get("related_urls", [])),
        ("related_emails", enrichment.get("related_emails", [])),
    )
    for _, values in indicator_groups:
        for value in values:
            try:
                indicator_type = identify_ioc(value)
            except ValueError:
                indicator_type = "unknown"
            related_indicators.append({"type": indicator_type, "value": value})

    malware = enrichment.get("malware", [])
    actors = enrichment.get("threat_actors", [])
    campaigns = enrichment.get("campaigns", [])
    techniques = enrichment.get("mitre_techniques", [])
    return {
        "related_malware": malware,
        "threat_actor": actors[0] if actors else None,
        "threat_actors": actors,
        "campaign": campaigns[0] if campaigns else None,
        "campaigns": campaigns,
        "mitre_technique": techniques[0] if techniques else None,
        "mitre_techniques": techniques,
        "related_indicators": related_indicators,
        # Keep the original fields available to existing clients.
        "related_domains": enrichment.get("related_domains", []),
        "related_ips": enrichment.get("related_ips", []),
        "malware": malware,
    }
