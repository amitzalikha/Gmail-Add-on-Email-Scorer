import math
from typing import List, Dict
from .detector import DetectionResult
from .constants import WEIGHTS, THRESHOLD_MALICIOUS, THRESHOLD_SUSPICIOUS

class EmailThreatScorer:
    def __init__(self, detectors: List):
        """
        Initializes the scorer with a list of active detector modules.
        """
        self.detectors = detectors

    def evaluate_email(self, email_data: Dict) -> Dict:
        """
        Processes email data through all detectors and calculates the final threat report.
        """
        results: Dict[str, DetectionResult] = {}
        
        # Run all detectors and collect results
        for detector in self.detectors:
            res = detector.analyze(
                subject=email_data.get("subject", ""),
                sender=email_data.get("sender", ""),
                reply_to=email_data.get("reply_to"),
                body=email_data.get("body", ""),
                spf=email_data.get("spf"),
                dkim=email_data.get("dkim")
            )
            
            # Normalize detector names to match WEIGHTS keys 
            key = res.detector_name.lower().replace(" & ", "_").replace(" ", "_")
            results[key] = res

        # Calculate the weighted total score
        total_weighted_score = 0.0
        
        for category, weight in WEIGHTS.items():
            # Find the result key that matches the current category weight
            res_key = next((k for k in results.keys() if category in k), None)
            if not res_key:
                continue
                
            raw_score = results[res_key].risk_score
            
            # Calculate the score for this category based on its weight
            total_weighted_score += (raw_score * weight)

        # When multiple independent detectors fire, the overall risk increases because 
        # independent signals are converging on a potential threat so add to it accordingly
        detectors_fired = sum(1 for r in results.values() if r.risk_score > 0)
        
        if detectors_fired >= 4:
            total_weighted_score *= 1.35   
        elif detectors_fired >= 3:
            total_weighted_score *= 1.20   
        elif detectors_fired >= 2:
            total_weighted_score *= 1.10   

        # Final score calculation, rounded up to ensure even small threats are surfaced
        final_score = min(math.ceil(total_weighted_score), 100)
        
        # Prepare the display order 
        DISPLAY_ORDER = [
            "content_urgency",
            "sender_identity",
            "links_urls",
            "authentication",
            "homoglyph",
        ]

        def _order_key(name: str) -> int:
            for i, prefix in enumerate(DISPLAY_ORDER):
                if prefix in name:
                    return i
            return len(DISPLAY_ORDER)

        # Create a sorted breakdown for the final report
        ordered_breakdown = {
            name: {"score": r.risk_score, "flags": r.flags}
            for name, r in sorted(results.items(), key=lambda kv: _order_key(kv[0]))
        }

        return {
            "score": final_score,
            "verdict": self._get_verdict(final_score, results),
            "trust_applied": False, 
            "breakdown": ordered_breakdown,
        }

    def _get_verdict(self, score: int, results: Dict) -> str:
        """
        Determines the final verdict based on the calculated score and high-confidence triggers.
        """
        if score >= THRESHOLD_MALICIOUS:
            return "MALICIOUS"
            
        if score >= THRESHOLD_SUSPICIOUS:
            return "SUSPICIOUS"
            
      # Auth failure alone is too noisy, self sent and forwarded emails
      # often fail SPF/DKIM but are completely harmless.
      # So we only escalate to SUSPICIOUS if at least one other detector
      # (content, links, sender,...) fires at high confidence (≥60).
        non_auth_results = {k: v for k, v in results.items() if k != "authentication"}
        high_confidence_non_auth = any(r.risk_score >= 60 for r in non_auth_results.values())
        if high_confidence_non_auth and score >= 25:
            return "SUSPICIOUS"
            
        return "SAFE"