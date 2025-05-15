import spacy
import csv
from pathlib import Path
from collections import defaultdict
from spacy.matcher import PhraseMatcher
import os
import re


TAXONOMY = {
    "Information": [
        "VPN",
        "buffer overflow",
        "authentication",
        "password",
        "2fa",
        "third - party",
        "remediation",
        "certification",
        "training",
        "CISA",
        "session hijacking",
        "access",
        "support system",
        "personal information",
        "data exfiltration",
        "personal data exposure",
        "vendor relationship",
        "DDoS",
        "vulnerability",
        "ransomware",
        "payload",
        "backdoor",
        "patch",
        "zero - day",
        "DMZ",
        "supply chain",
        "source code",
        "credential",
        "internal",
        "ciso",
        "admin right",
        "insider threat",
        "employee misconduct",
        "customer data",
        "scam call",
        "environment",
        "exposure",
        "forensic",
        "CVE",
        "malicious activity",
        "risk",
        "threat actor",
        "intrusion",
        "compromise",
        "brute - force attack",
        "ssh",
        "login",
        "software update",
        "configuration",
        "anonymize tunnel",
        "proxy",
        "attack",
        "indicator of compromise",
        "attacker",
        "IP address",
        "username",
        "target",
        "hack",
        "spam",
        "SMS",
        "log monitoring",
        "mitigation",
        "detection",
        "install",
        "public - face",
        "script",
        "investigation",
        "confidential",
        "api token",
        "SSL",
        "IntelBroker",
        "adversary",
        "kill chain",
        "LastActive date",
        "malware",
        "scrape operation",
        "BreachForums",
        "social - engineering",
        "Microsoft Windows",
        "blue screen of death",
        "cloud",
        "manual recovery process",
        "update rollout",
        "malicious action",
        "flaw",
        "recommendation",
        "advisory",
        "security team monitor",
        "notification",
        "account lockdown",
        "social security number",
        "name",
        "date of birth",
        "employee data",
        "exam",
        "data management",
        "security firm",
        "email",
        "phone number",
        "criminal intent",
        "rogue employee",
        "incident",
        "Shell",
        "responsible disclosure",
        "PSIRT",
        "CVE assignment",
        "remediation process",
        "software",
        "outage",
        "MFA",
        "infrastructure"
    ],
    "Consequence": [
        "data exfiltration",
        "espionage",
        "theft",
        "movement",
        "account takeover",
        "reputational",
        "regulatory scrutiny",
        "loss",
        "global",
        "disruption",
        "impact",
        "customer trust",
        "PII exposure",
        "social engineering",
        "customer notification",
        "privilege escalation",
        "business contact leak",
        "extortion",
        "credential exposure",
        "supply chain risk",
        "rumor management",
        "penalty",
        "settlement",
        "public disclosure",
        "negligent minimization",
        "malware exfiltration",
        "service disruption",
        "outage",
        "compromise",
        "publication of unauthorized file",
        "cancellation",
        "stock value drop",
        "investigation",
        "service downtime",
        "access",
        "infection",
        "data breach",
        "customer risk",
        "class action",
        "data leak",
        "scam call to",
        "misuse of data",
        "termination",
        "company breach",
        "product vulnerability",
        "financial fraud",
        "confidential",
    ],
    "Trend/Analysis": [
        "state - sponsor campaign",
        "target",
        "supply chain risk",
        "delay",
        "trend",
        "pattern",
        "concern",
        "accountability",
        "evolution",
        "targeting",
        "geopolitical threat",
        "response",
        "timeline",
        "improvement",
        "vendor management",
        "disclosure",
        "active exploitation",
        "patch management",
        "security advisory",
        "tracking",
        "patch release",
        "transparency",
        "rumor control",
        "sector - wide",
        "regulatory action",
        "enforcement",
        "surge",
        "opportunistic",
        "recommendation",
        "minimized",
        "limited",
        "broad",
        "responsible disclosure"
    ]
}

INPUT_ROOT = Path(r"E:\Documents\TCC\phrases extracted")
OUTPUT_ROOT = Path(r"E:\Documents\TCC\categorized_results")



nlp = spacy.load("en_core_web_sm")

def create_lemmatized_patterns(terms):
    """Convert terms to their lemmatized forms for matching"""
    patterns = []
    for term in terms:
        doc = nlp(term)
        lemmatized = " ".join([token.lemma_ for token in doc])
        patterns.append(nlp(lemmatized))
    return patterns

matchers = {}
for category, terms in TAXONOMY.items():
    matcher = PhraseMatcher(nlp.vocab, attr="LEMMA")
    filtered_terms = [term for term in terms if not term.startswith("CVE")]
    patterns = create_lemmatized_patterns(filtered_terms)
    if patterns:  
        matcher.add(category, patterns)
        matchers[category] = matcher

def process_file(input_path):
    """Process a single file with lemmatization-aware matching"""
    with open(input_path, "r", encoding="utf-8") as f:
        text = f.read()
    
    doc = nlp(text)
    results = defaultdict(lambda: defaultdict(int))
    
    for category, matcher in matchers.items():
        matches = matcher(doc)
        for _, start, end in matches:
            matched_span = doc[start:end]
            original_text = matched_span.text
            results[category][original_text] += 1
    
    cve_pattern = r'\bCVE\s*-\s*\d{4}\s*-\s*\d{4,}\b'
    cve_matches = re.findall(cve_pattern, text, flags=re.IGNORECASE)
    for cve in cve_matches:
        normalized_cve = re.sub(r'\s*-\s*', '-', cve).upper()
        results["Information"][normalized_cve] += 1
    
    return results

def save_results(results, output_path):
    """Save results to CSV: Category, Term, Count"""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Category", "Term", "Count"])
        for category, terms in results.items():
            for term, count in terms.items():
                writer.writerow([category, term, count])

for input_dir in INPUT_ROOT.glob("*"):
    if input_dir.is_dir():
        output_dir = OUTPUT_ROOT / input_dir.name
        os.makedirs(output_dir, exist_ok=True)
        
        print(f"\nProcessing {input_dir.name}...")
        
        for input_file in input_dir.glob("*.txt"):
            results = process_file(input_file)
            output_file = output_dir / f"{input_file.stem}_analysis1.csv"
            save_results(results, output_file)
            print(f"  Processed {input_file.name} -> {output_file.name}")

print("\nComplete! All subfolders processed.")
print(f"Total categorized results in: {OUTPUT_ROOT}")

