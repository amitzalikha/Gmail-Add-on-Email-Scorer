import math
from typing import List, Dict
from .detector import DetectionResult
from .constants import WEIGHTS, TRUST_DAMPENING_FACTOR, THRESHOLD_MALICIOUS, THRESHOLD_SUSPICIOUS

class EmailThreatScorer:
    def __init__(self, detectors: List):
        # Initialize the scorer with a list of active detector modules
        self.detectors = detectors

    def evaluate_email(self, email_data: Dict) -> Dict:
        results: Dict[str, DetectionResult] = {}
        
        # Execute all detectors and collect individual results 
        for detector in self.detectors:
            res = detector.analyze(
                subject=email_data.get("subject", ""),
                sender=email_data.get("sender", ""),
                reply_to=email_data.get("reply_to"),
                body=email_data.get("body", ""),
                spf=email_data.get("spf"),
                dkim=email_data.get("dkim")
            )
            # Normalize detector name to a clean key, matching WEIGHTS keys exactly
            key = res.detector_name.lower().replace(" & ", "_").replace(" ", "_")
            results[key] = res

        # Determine the Trust Context
        #  Check if the email passed both cryptographic authentication (SPF/DKIM)
        # and has no lookalike domain detections
        is_authenticated = (
            "authentication" in results and 
            results["authentication"].risk_score == 0
        )
        is_not_lookalike = (
            "homoglyph_&_lookalike_domains" in results and 
            results["homoglyph_&_lookalike_domains"].risk_score == 0
        )
        # High trust is granted only if both technical checks pass 
        has_high_trust = is_authenticated and is_not_lookalike

        # Calculate weighted sum 
        total_weighted_score = 0.0
        actual_dampening_happened = False
        # Match the category weight to the correct detector result
        for category, weight in WEIGHTS.items():
            res_key = next((k for k in results.keys() if category in k), None)
            if not res_key:
                continue
                
            raw_score = results[res_key].risk_score
            # Apply trust dampening to 'softer' signals like language and sender names if the technical foundation (SPF/DKIM) is solid
            if has_high_trust and category in ["content_urgency", "sender_identity"]:
                effective_score = raw_score * TRUST_DAMPENING_FACTOR
                if raw_score > 0:
                    actual_dampening_happened = True
            else:
                effective_score = raw_score
                
            total_weighted_score += (effective_score * weight)

        # When multiple independent detectors trigger
        #  the overall risk increases because multiple independent signals are converging on a threat
        detectors_fired = sum(1 for r in results.values() if r.risk_score > 0)
        if detectors_fired >= 4:
            # 35% boost for high convergence
            total_weighted_score *= 1.35   
        elif detectors_fired >= 3:
            # 20% boost for 3 signals
            total_weighted_score *= 1.20   
        elif detectors_fired >= 2:
            # 10% boost for 2 signals
            total_weighted_score *= 1.10   

        # Final score calculation rounded up to avoid missing small threats
        final_score = min(math.ceil(total_weighted_score), 100)
        
       # Define the order in which results should be displayed to the user
        DISPLAY_ORDER = [
            "content_urgency",
            "sender_identity",
            "links_urls",
            "authentication",
            "homoglyph",
        ]

        # Helper function to sort the breakdown by the priority list above
        def _order_key(name: str) -> int:
            for i, prefix in enumerate(DISPLAY_ORDER):
                if prefix in name:
                    return i
            return len(DISPLAY_ORDER)

        ordered_breakdown = {
            name: {"score": r.risk_score, "flags": r.flags}
            for name, r in sorted(results.items(), key=lambda kv: _order_key(kv[0]))
        }

        # Return the final analysis report
        return {
            "score": final_score,
            "verdict": self._get_verdict(final_score, results),
            "trust_applied": has_high_trust and actual_dampening_happened,
            "breakdown": ordered_breakdown,
        }

    def _get_verdict(self, score: int, results: Dict) -> str:
        if score >= THRESHOLD_MALICIOUS:
            return "MALICIOUS"
        if score >= THRESHOLD_SUSPICIOUS:
            return "SUSPICIOUS"
        # Only escalate to SUSPICIOUS from SAFE when a single detector fires
        # at very high confidence (≥60) AND the overall score is non-trivial
        # This prevents a single noisy detector from overriding a low total score
        high_confidence_hit = any(r.risk_score >= 60 for r in results.values())
        if high_confidence_hit and score >= 25:
            return "SUSPICIOUS"
        return "SAFE"