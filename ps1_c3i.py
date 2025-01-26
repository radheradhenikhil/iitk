
import re
import spacy
import json
from fuzzywuzzy import process
import requests

# Load spaCy model for Named Entity Recognition (NER)
nlp = spacy.load("en_core_web_sm")

# Load MITRE ATT&CK tactics and techniques from a JSON file (can be updated externally)
MITRE_ATTACK_MAPPING = {
    "Tactics": {
        "Initial Access": "TA0001",
        "Execution": "TA0002",
        "Lateral Movement": "TA0008"
    },
    "Techniques": {
        "Spear Phishing Attachment": "T1566.001",
        "PowerShell": "T1059.001"
    }
}

# Define the main function for threat intelligence extraction
def extract_threat_intelligence(report_text):
    # Initialize the output dictionary
    extracted_data = {
        'IoCs': {
            'IP addresses': [],
            'Domains': [],
            'Emails': [],
            'File Hashes': []
        },
        'TTPs': {
            'Tactics': [],
            'Techniques': []
        },
        'Threat Actor(s)': [],
        'Malware': [],
        'Targeted Entities': []
    }

    # Define regex patterns for IoC extraction
    regex_patterns = {
        'IP addresses': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        'Domains': r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
        'Emails': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'File Hashes': r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
    }

    # Extract IoCs
    for ioc_type, pattern in regex_patterns.items():
        extracted_data['IoCs'][ioc_type] = list(set(re.findall(pattern, report_text)))

    # Use spaCy for NER to extract entities
    doc = nlp(report_text)
    for ent in doc.ents:
        if ent.label_ == "ORG":
            extracted_data['Targeted Entities'].append(ent.text)
        elif ent.label_ == "PERSON":
            extracted_data['Threat Actor(s)'].append(ent.text)

    # Deduplicate NER results
    extracted_data['Targeted Entities'] = list(set(extracted_data['Targeted Entities']))
    extracted_data['Threat Actor(s)'] = list(set(extracted_data['Threat Actor(s)']))

    # Extract malware names using a simple regex
    malware_candidates = re.findall(r'\b[A-Z][a-zA-Z0-9_-]{3,}\b', report_text)
    for malware in malware_candidates:
        if "malware" in report_text.lower():
            extracted_data['Malware'].append({
                'Name': malware,
                'Details': 'Details can be enriched via an external API'
            })

    # Deduplicate malware results
    extracted_data['Malware'] = [dict(t) for t in {tuple(d.items()) for d in extracted_data['Malware']}]

    # Map TTPs to MITRE ATT&CK
    for category, mapping in MITRE_ATTACK_MAPPING.items():
        for phrase, ttp_code in mapping.items():
            if phrase.lower() in report_text.lower():
                extracted_data['TTPs'][category].append({ttp_code: phrase})

    return extracted_data

# Example usage
if __name__ == "__main__":
    report_text = '''
A new campaign by the Lazarus Group has been detected targeting defense contractors. 
The attackers delivered a malicious payload, identified as WannaCry ransomware, through phishing emails containing Excel macros. 
The initial access was achieved using a vulnerability in Microsoft Office. The malware communicated with command-and-control servers at 192.168.50.5 and 10.0.0.7, as well as malicious domains like steal-data.org and hacker-base.net. 
Hashes of the malicious files include e3c5695c4a8c09d8f4e7e453f7f3d40a and af5caaaf89f1ea3b48dc3561e3e82c28. 
Additionally, the attackers used tools such as Mimikatz and PowerShell scripts for credential harvesting and lateral movement. 
Targeted entities include companies in the aerospace and defense sectors. The Lazarus Group is suspected of being linked to a nation-state. 
'''



    # Extract threat intelligence
    output = extract_threat_intelligence(report_text)

    # Print the results
    print(json.dumps(output, indent=4))
    
    
    
    
    
