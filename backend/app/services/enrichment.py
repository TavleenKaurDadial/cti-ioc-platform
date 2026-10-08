from copy import deepcopy
from datetime import datetime, timezone


# Synthetic examples only. These names and relationships are demonstration data,
# not claims about live indicators or real threat activity.
DEMO_INTELLIGENCE = {
    ("ipv4", "8.8.8.8"): {
        "reputation": "Benign",
        "country": "United States",
        "asn": "AS15169",
        "organization": "Google LLC (public DNS)",
        "sources": ["Demo Baseline Feed"],
    },
    ("ipv4", "203.0.113.10"): {
        "reputation": "Malicious",
        "country": "Example Region",
        "asn": "AS64500",
        "organization": "Example Hosting Network",
        "related_domains": ["login-update.example"],
        "malware": ["ExampleRAT"],
        "threat_actors": ["Example Group"],
        "campaigns": ["Credential Lure Demo"],
        "mitre_techniques": ["T1566.002", "T1071.001"],
        "sources": ["Demo Threat Feed", "Demo Reputation Feed"],
    },
    ("domain", "login-update.example"): {
        "reputation": "Malicious",
        "related_ips": ["203.0.113.10"],
        "related_urls": ["https://login-update.example/session"],
        "malware": ["ExampleRAT", "ExampleStealer"],
        "threat_actors": ["Example Group"],
        "campaigns": ["Credential Lure Demo"],
        "mitre_techniques": ["T1566.002", "T1059.001", "T1071.001"],
        "sources": ["Demo Domain Feed", "Demo Threat Feed"],
    },
    ("domain", "cdn-content.example"): {
        "reputation": "Suspicious",
        "related_ips": ["198.51.100.24"],
        "malware": ["ExampleStealer"],
        "campaigns": ["Staged Payload Demo"],
        "mitre_techniques": ["T1105"],
        "sources": ["Demo Passive DNS Feed"],
    },
    ("url", "https://login-update.example/session"): {
        "reputation": "Malicious",
        "related_domains": ["login-update.example"],
        "related_ips": ["203.0.113.10"],
        "malware": ["ExampleRAT"],
        "threat_actors": ["Example Group"],
        "campaigns": ["Credential Lure Demo"],
        "mitre_techniques": ["T1566.002", "T1071.001"],
        "sources": ["Demo URL Feed", "Demo Threat Feed"],
    },
    ("email", "analyst@example.invalid"): {
        "reputation": "Suspicious",
        "related_domains": ["login-update.example"],
        "malware": ["ExampleStealer"],
        "threat_actors": ["Example Group"],
        "campaigns": ["Credential Lure Demo"],
        "mitre_techniques": ["T1566.001"],
        "sources": ["Demo Email Feed"],
    },
    ("sha256", "a" * 64): {
        "reputation": "Malicious",
        "malware": ["ExampleStealer"],
        "threat_actors": ["Example Group"],
        "campaigns": ["Staged Payload Demo"],
        "mitre_techniques": ["T1204.002", "T1105"],
        "sources": ["Demo File Hash Feed", "Demo Threat Feed"],
    },
    ("md5", "d41d8cd98f00b204e9800998ecf8427e"): {
        "reputation": "Unknown",
        "sources": ["Demo File Hash Feed"],
    },
    ("sha1", "0123456789abcdef0123456789abcdef01234567"): {
        "reputation": "Suspicious",
        "malware": ["ExampleRAT"],
        "sources": ["Demo File Hash Feed"],
    },
}


def enrich_ioc(value: str, ioc_type: str) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    enrichment = {
        "reputation": "Unknown",
        "country": None,
        "asn": None,
        "organization": None,
        "related_domains": [],
        "related_ips": [],
        "related_urls": [],
        "related_emails": [],
        "malware": [],
        "threat_actors": [],
        "campaigns": [],
        "mitre_techniques": [],
        "sources": ["Demo Feed"],
        "first_seen": now,
        "last_seen": now,
    }
    enrichment.update(deepcopy(DEMO_INTELLIGENCE.get((ioc_type, value), {})))
    return enrichment
