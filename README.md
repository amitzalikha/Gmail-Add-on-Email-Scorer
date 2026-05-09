# Gmail-Add-on-Email-Scorer

Malicious Email Scorer
A real time email threat detection system built as a Gmail Add-on. 
When you open an email in Gmail, the add-on automatically analyzes it and returns a risk score, a verdict, and a plain-English breakdown of every red flag found.


**What It Does**

Scans every email you open in Gmail instantly
Returns a score from 0 to 100 and one of three verdicts: SAFE, SUSPICIOUS, or MALICIOUS
Shows exactly which signals triggered the score in plain language
Covers 7 attack categories: phishing links, credential harvesting, financial scams, CEO fraud / BEC, delivery scams, tech support scams, and homoglyph domain impersonation.

---

## **System Architecture**

```text
Gmail (Browser)
      │
      │  Opens email → triggers Add-on
      ▼
Google Apps Script
      │
      │  Extracts email data → POST /analyze
      ▼
FastAPI Backend (main.py)
      │
      ├── AuthenticationDetector — SPF / DKIM verification
      ├── SenderDetector         — Display name spoofing, reply-to hijacking
      ├── ContentDetector        — Urgency, sensitive info, CEO fraud, scam language
      ├── LinkDetector           — Suspicious TLDs, shorteners, dangerous files
      └── HomoglyphDetector      — Lookalike domains 
          │
          ▼
    EmailThreatScorer (scorer.py)
          │
          ▼
    JSON Response → Gmail Add-on Panel

     ---

__Backend (Python / FastAPI)__
The backend runs in a Docker container and exposes a single endpoint: POST /analyze. It receives the email data from the Gmail Add-on, runs it through 5 independent detectors, and returns a score with a full breakdown.

__Gmail Add-on (Google Apps Script)__
The frontend runs inside Gmail as a side panel. When you open an email it extracts the subject, sender, body, and authentication headers, sends them to the backend, and renders the result as a card with ✗ flags and a verdict.

---

**Scoring Logic**

__1. Detectors__
Each detector analyzes one aspect of the email independently and returns a raw risk score from 0 to 100.

| Detector | Inspection Focus |
| :--- | :--- |
| **Authentication** | Validates **SPF** and **DKIM** headers to ensure the email's source is legitimate. |
| **Identity Verification** | Identifies display name spoofing, reply-to hijacking, and brand impersonation from free providers. |
| **Content & Urgency** | Analyzes linguistic intent across **7 attack patterns** using regex-based phrase matching. |
| **Links & URLs** | Scans for suspicious TLDs, URL shorteners, dangerous extensions, and deceptive plain-text URLs. |
| **Domain Integrity** | Detects **Homoglyph** attacks and look-alike domains using character substitution techniques. |




__2. Weighted Score__
The final risk assessment isn't a simple average. Instead, each detector's score is multiplied by a specific **weight** based on its reliability and impact. This ensures that high-risk indicators (like malicious links) influence the final result more than noisier signals.

| Detector | Weight | Rationale |
| :--- | :---: | :--- |
| **Links & URLs** | **35%** | Direct threat vector; the most common method for executing an attack. |
| **Content & Urgency** | **30%** | Deep behavioral analysis covering 7 distinct attack categories. |
| **Sender Identity** | **15%** | Highly effective, though it occasionally overlaps with authentication checks. |
| **Authentication** | **15%** | Essential, but weighted lower due to false positives in forwarded or internal mail. |
| **Homoglyph** | **5%** | A rare attack type, but provides near-certainty when a match is found. |




__3. Compounding Bonus__
When multiple independent detectors fire at the same time, the total score gets a bonus, because **converging signals are stronger evidence than a single signal alone**.



### **4. Final Verdict**
The final risk level is determined based on the total weighted score:

| Score Range | Verdict | Action / Icon |
| :--- | :--- | :---: |
| **0 - 24** | **SAFE** | ✅ |
| **25 - 59** | **SUSPICIOUS** | ⚠️ |
| **60 - 100** | **MALICIOUS** | 🚨 |

---
   
A SUSPICIOUS escalation also triggers if any non-authentication detector scores ≥ 60 and the total is ≥ 25, even if the weighted total is below the threshold. 

---

**Running the Backend**

Docker

Build the image:

```bash
docker build -t email-scorer .

Run the Container:

```bash
docker run -p 8000:8000 email-scorer 

The API will be available at http://localhost:8000.
To verify it's running:
bashcurl http://localhost:8000/
# {"status": "online", "message": "Email Threat Scorer is active"}

API
POST /analyze
Request body:
json{
  "subject": "Action Required: Verify your account",
  "sender": "support@paypa1.xyz",
  "body": "Please verify your credit card details immediately.",
  "reply_to": "",
  "spf": "",
  "dkim": "",
  "auth_results": ""
}

Response:
json{
  "score": 81,
  "verdict": "MALICIOUS",
  "trust_applied": false,
  "breakdown": {
    "content_urgency": { "score": 100, "flags": ["..."] },
    "links_urls":      { "score": 70,  "flags": ["..."] },
    "authentication":  { "score": 60,  "flags": ["..."] }
  }
}

Gmail Add-on Setup

Open Google Apps Script and create a new project
Paste the contents of addon.js into Code.gs
Paste the contents of appsscript.json into the manifest file
In the Apps Script editor go to Project Settings → Script Properties and add:

Key: BACKEND_URL - Value: your backend URL (e.g. your ngrok URL + /analyze)


Go to Deploy → Test deployments to install the add-on in Gmail
Open any email in Gmail — the add-on panel will appear automatically on the right


Note: The backend must be publicly accessible for the Gmail Add-on to reach it. During development you can use ngrok to expose your local Docker container.

---
__Project Structure__
├── main.py              # FastAPI entry point and request model
├── Dockerfile           # Container definition
├── Engine/
│   ├── detector.py      # All 5 detector classes
│   ├── scorer.py        # Weighted scoring engine and verdict logic
│   └── constants.py     # Weights, thresholds, and tuning parameters
├── addon.js             # Gmail Add-on frontend (Google Apps Script)
└── appsscript.json      # Add-on manifest and OAuth scopes


