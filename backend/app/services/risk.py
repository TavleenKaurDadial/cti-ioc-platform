def calculate_risk(enrichment: dict) -> tuple[float, float, list[str]]:
    """Return a deterministic demo score, confidence, and human-readable factors."""
    score = 0.0
    factors = []

    reputation = enrichment.get("reputation", "Unknown").lower()
    reputation_points = {"malicious": 40, "suspicious": 25}.get(reputation, 0)
    if reputation_points:
        score += reputation_points
        factors.append(f"{reputation.capitalize()} reputation (+{reputation_points})")

    malware_count = len(enrichment.get("malware", []))
    if malware_count:
        points = min(malware_count * 15, 30)
        score += points
        factors.append(f"Associated with known malware (+{points})")

    actor_count = len(enrichment.get("threat_actors", []))
    if actor_count:
        points = min(actor_count * 15, 30)
        score += points
        factors.append(f"Associated with a known threat actor (+{points})")

    campaign_count = len(enrichment.get("campaigns", []))
    if campaign_count:
        points = min(campaign_count * 10, 20)
        score += points
        factors.append(f"Associated with a known campaign (+{points})")

    technique_count = len(enrichment.get("mitre_techniques", []))
    if technique_count:
        points = min(technique_count * 5, 15)
        score += points
        factors.append(f"Observed MITRE ATT&CK techniques (+{points})")

    sources = enrichment.get("sources", [])
    confidence = min(0.4 + 0.08 * len(sources) + 0.08 * technique_count, 0.98)
    if not factors:
        factors.append("No elevated-risk indicators found in the demo intelligence")

    return round(min(score, 100), 2), round(confidence, 2), factors
