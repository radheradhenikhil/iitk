# 🛡️ **Uncovering Threat Intelligence from Cybersecurity Reports**

---

## 🌟 **Overview**
In today's cybersecurity landscape, the ability to extract actionable intelligence from unstructured threat reports is critical. This project leverages **Natural Language Processing (NLP)** to automatically uncover Indicators of Compromise (IoCs), Tactics, Techniques, and Procedures (TTPs), malware details, and targeted entities from natural language threat reports. 

The solution is aligned with the **MITRE ATT&CK Framework** and aims to automate and simplify threat intelligence extraction for cybersecurity professionals.

---

## ⚙️ **Features**
- **IoC Extraction**: Detects IP addresses, domains, file hashes, and email addresses.
- **TTP Identification**: Maps tactics and techniques to the **MITRE ATT&CK Framework**.
- **Malware Analysis**: Extracts malware names and enriches details using APIs (future scope).
- **Threat Actor Detection**: Identifies adversarial groups or individuals.
- **Target Identification**: Highlights targeted industries or organizations.
- **Future Scope**: Incorporates API-based enrichment (e.g., VirusTotal).

---

## 🧰 **Installation**

Follow these steps to set up the project locally:

1. Clone the repository:
   ```bash
   git clone https://github.com/radheradhenikhil/iitk.git
   ```
2. Navigate to the project directory:
   ```bash
   cd iitk
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

   **Requirements:**
   - `re`
   - `spacy`
   - `json`
   - `fuzzywuzzy`
   - `requests`

4. Run the script:
   ```bash
   python threat_intelligence_extractor.py
   ```

---

## 🛠️ **Usage**

1. Prepare the input as a natural language threat report (string format).
2. Pass the report to the script for processing.

### **Example Input:**
```python
report_text = '''
A new campaign by the Lazarus Group has been detected targeting defense contractors. 
The attackers delivered a malicious payload, identified as WannaCry ransomware, through phishing emails containing Excel macros. 
The initial access was achieved using a vulnerability in Microsoft Office. The malware communicated with command-and-control servers at 192.168.50.5 and 10.0.0.7, as well as malicious domains like steal-data.org and hacker-base.net. 
Hashes of the malicious files include e3c5695c4a8c09d8f4e7e453f7f3d40a and af5caaaf89f1ea3b48dc3561e3e82c28. 
Additionally, the attackers used tools such as Mimikatz and PowerShell scripts for credential harvesting and lateral movement. 
Targeted entities include companies in the aerospace and defense sectors. The Lazarus Group is suspected of being linked to a nation-state.
'''
```

### **Example Output:**
```json
{
    "IoCs": {
        "IP addresses": [
            "192.168.50.5",
            "10.0.0.7"
        ],
        "Domains": [
            "steal-data.org",
            "hacker-base.net"
        ],
        "Emails": [],
        "File Hashes": [
            "af5caaaf89f1ea3b48dc3561e3e82c28",
            "e3c5695c4a8c09d8f4e7e453f7f3d40a"
        ]
    },
    "TTPs": {
        "Tactics": [
            {
                "TA0001": "Initial Access"
            },
            {
                "TA0008": "Lateral Movement"
            }
        ],
        "Techniques": [
            {
                "T1059.001": "PowerShell"
            }
        ]
    },
    "Threat Actor(s)": [
        "Mimikatz"
    ],
    "Malware": [
        {
            "Name": "WannaCry",
            "Details": "Details can be enriched via an external API"
        }
    ],
    "Targeted Entities": [
        "Aerospace and Defense Sectors"
    ]
}
```

---

## 📂 **Project Structure**
```
.
├── README.md
├── requirements.txt
├── threat_intelligence_extractor.py
└── sample_reports/
    └── report1.txt
```

---

## ✨ **Team RadheByte**
- **Team Leader**: [Nikhil Agarwal](https://linkedin.com/in/nikhilagarwal99)
  - **Email**: nikhilagarwalnda@gmail.com
  - **GitHub**: [radheradhenikhil](https://github.com/radheradhenikhil)
- **Contributors**: Team members assisted in research and problem statement selection.

---

## 📝 **Summary**
This project, developed by **Team RadheByte**, automates the extraction of threat intelligence from cybersecurity reports. It is built to save time, enhance accuracy, and provide structured outputs for analysts. The project has immense potential for future enhancements, such as API integrations and real-time processing.

---

## 🌐 **Repository Link**
🔗 [GitHub Repository](https://github.com/radheradhenikhil/iitk)

---

### 🚀 **Future Scope**
- Incorporate APIs for malware enrichment (e.g., VirusTotal).
- Add visualization for threat analysis.
- Enhance NLP models for better accuracy.

---

## 🔖 **License**
This project is open-source and available under the [MIT License](https://opensource.org/licenses/MIT).

