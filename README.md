# Gmail-Add-on-Email-Scorer

Malicious Email Scorer
**Real-time email threat detection system built as a Gmail Add-on.**
When you open an email in Gmail, the add-on automatically analyzes it and returns a risk score, a verdict, and a plain-English breakdown of every red flag found.

---

**What It Does**

*   **Instant Scanning:** Scans every email you open in Gmail instantly.
*   **Dynamic Scoring:** Returns a score from 0 to 100 with a clear verdict: **SAFE**, **SUSPICIOUS**, or **MALICIOUS**.
*   **Transparent Analysis:** Shows exactly which signals triggered the score in plain language.
*   **Broad Protection:** Covers 7 attack categories including phishing links, credential harvesting, financial scams, CEO fraud (BEC), delivery scams, tech support scams, and homoglyph domain impersonation.

  
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
```


# **Design & Extensibility**

### **Abstract Foundation**
The system is built with a focus on **modularity** and **scalability**. I implemented an **Abstract Base Class (Detector)** for all analysis engines. This design pattern ensures:

*   **Easy Integration:** Adding a new security check (e.g., AI-based sentiment analysis or Image scanning) is as simple as creating a new class that inherits from the base detector.
*   **Standardized Output:** Every detector is forced to implement a consistent interface, ensuring the scoring engine can process results without knowing the internal logic of each module.
*   **Maintainability:** Changes to the scoring logic or a specific detection method can be made in isolation without affecting the rest of the system.

### **Command & Strategy Patterns**
By decoupling the detection logic from the scoring engine, the system follows the **Open/Closed Principle** it is open for extension but closed for modification.


### **Backend (Python / FastAPI)**
The backend runs in a Docker container and exposes a single endpoint: POST /analyze. It receives the email data from the Gmail Add-on, runs it through 5 independent detectors, and returns a score with a full breakdown.


### **Gmail Add-on (Google Apps Script)**
The frontend runs inside Gmail as a side panel. When you open an email it extracts the subject, sender, body, and authentication headers, sends them to the backend, and renders the result as a card with ✗ flags and a verdict.

---

# **Scoring Logic**

### **1. Detectors**
Each detector analyzes one aspect of the email independently and returns a raw risk score from 0 to 100.

| Detector | Inspection Focus |
| :--- | :--- |
| **Authentication** | Validates **SPF** and **DKIM** headers to ensure the email's source is legitimate. |
| **Identity Verification** | Identifies display name spoofing, reply-to hijacking, and brand impersonation from free providers. |
| **Content & Urgency** | Analyzes linguistic intent across **7 attack patterns** using regex-based phrase matching. |
| **Links & URLs** | Scans for suspicious TLDs, URL shorteners, dangerous extensions, and deceptive plain-text URLs. |
| **Domain Integrity** | Detects **Homoglyph** attacks and look-alike domains using character substitution techniques. |




### **2. Weighted Score**
The final risk assessment isn't a simple average. Instead, each detector's score is multiplied by a specific **weight** based on its reliability and impact. This ensures that high-risk indicators (like malicious links) influence the final result more than noisier signals.

| Detector | Weight | Rationale |
| :--- | :---: | :--- |
| **Links & URLs** | **35%** | Direct threat vector; the most common method for executing an attack. |
| **Content & Urgency** | **30%** | Deep behavioral analysis covering 7 distinct attack categories. |
| **Sender Identity** | **15%** | Highly effective, though it occasionally overlaps with authentication checks. |
| **Authentication** | **15%** | Essential, but weighted lower due to false positives in forwarded or internal mail. |
| **Homoglyph** | **5%** | A rare attack type, but provides near-certainty when a match is found. |




### **3. Compounding Bonus**
When multiple independent detectors fire at the same time, the total score gets a bonus, because **converging signals are stronger evidence than a single signal alone**.



### **4. Final Verdict**
The final risk level is determined based on the total weighted score:

| Score Range | Verdict | Action / Icon |
| :--- | :--- | :---: |
| **0 - 24** | **SAFE** | ✅ |
| **25 - 59** | **SUSPICIOUS** | ⚠️ |
| **60 - 100** | **MALICIOUS** | 🚨 |
   
A SUSPICIOUS escalation also triggers if any non-authentication detector scores ≥ 60 and the total is ≥ 25, even if the weighted total is below the threshold. 

---

**Running the Backend**

Docker:

Build the image:

```bash
docker build -t email-scorer .
```

Run the Container:

```bash
docker run -p 8000:8000 email-scorer 
```

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

---

## **Future Roadmap & Potential Extensions**

The current architecture's modularity allows for seamless integration of more advanced security features. Planned or potential enhancements include:

### **1. AI & Machine Learning Integration**
*   **LLM Analysis:** Integrating a Large Language Model to analyze the semantic meaning of emails, detecting subtle social engineering tactics that regex cannot catch.
*   **Anomaly Detection:** Training a model on a user's typical communication patterns to flag unusual requests (e.g., a sudden request for a wire transfer from a known contact).

### **2. Advanced Link & File Sandboxing**
*   **URL Unshortening:** Automatically expanding shortened URLs to inspect the final destination before the user clicks.
*   **Live Sandbox API:** Integrating with services like VirusTotal or Hybrid Analysis to scan attachments in a virtual environment in real-time.

### **3. Enhanced Identity Intelligence**
*   **Graph Analysis:** Building a "trust graph" based on previous interactions to lower the risk score for long-term, verified correspondents.
*   **BIMI Support:** Checking for Brand Indicators for Message Identification to verify official corporate logos in the Gmail UI.

### **4. User Feedback Loop**
*   **"Report False Positive" Button:** Allowing users to provide feedback directly from the Gmail Add-on, which can be used to fine-tune the detector weights (`scorer.py`) over time.
