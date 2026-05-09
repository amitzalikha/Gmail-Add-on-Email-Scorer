# main.py
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional



from Engine.scorer import EmailThreatScorer
from Engine.detector import (
    AuthenticationDetector, 
    SenderDetector, 
    ContentDetector, 
    LinkDetector, 
    HomoglyphDetector
)


app = FastAPI(
    title="Malicious Email Scorer API",
    description="Backend API for Gmail Add-on security analysis"
)

# ─── DATA MODELS ─────────────────────────────────────────────────────────────
class EmailAnalysisRequest(BaseModel):
    subject: str
    sender: str
    body: str
    reply_to: Optional[str] = None
    spf: Optional[str] = None
    dkim: Optional[str] = None

# ─── ENGINE SETUP ────────────────────────────────────────────────────────────
# Instantiate the detectors once at startup
active_detectors = [
    AuthenticationDetector(),
    SenderDetector(),
    ContentDetector(),
    LinkDetector(),
    HomoglyphDetector()
]

# Instantiate the scorer with the detectors
threat_engine = EmailThreatScorer(active_detectors)

# ─── ENDPOINTS ────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"status": "online", "message": "Email Threat Scorer is active"}

@app.post("/analyze")
async def analyze_email(request: EmailAnalysisRequest):
    """
    Receives email data from the Gmail Add-on and returns a 
    comprehensive maliciousness report.
    """
    try:
        # Convert Pydantic model to dictionary
        email_data = request.dict()
        
        # Process the email through the scoring engine
        report = threat_engine.evaluate_email(email_data)
        
        return report

    except Exception as e:
        # Security awareness: log the error but don't leak internals to client
        print(f"Error during analysis: {e}")
        raise HTTPException(status_code=500, detail="Internal analysis engine error")

# ─── EXECUTION ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Run the server 
    uvicorn.run(app, host="0.0.0.0", port=8000)


   