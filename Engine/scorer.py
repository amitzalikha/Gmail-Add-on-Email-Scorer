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
        
        # 1. Run all detectors and collect results
        for detector in self.detectors:
            res = detector.analyze(
                subject=email_data.get("subject", ""),
                sender=email_data.get("sender", ""),
                reply_to=email_data.get("reply_to"),
                body=email_data.get("body", ""),
                spf=email_data.get("spf"),
                dkim=email_data.get("dkim")
            )
            
            # Normalize detector names to match WEIGHTS keys (e.g., "Links & URLs" -> "links_urls")
            key = res.detector_name.lower().replace(" & ", "_").replace(" ", "_")
            results[key] = res

        # 2. Calculate the weighted total score
        # Trust dampening has been removed. All signals are now calculated at full weight.
        total_weighted_score = 0.0
        
        for category, weight in WEIGHTS.items():
            # Find the result key that matches the current category weight
            res_key = next((k for k in results.keys() if category in k), None)
            if not res_key:
                continue
                
            raw_score = results[res_key].risk_score
            
            # Calculate the score for this category based on its importance (weight)
            total_weighted_score += (raw_score * weight)

        # 3. Apply Compounding Bonus
        # When multiple independent detectors fire, the overall risk increases because 
        # independent signals are converging on a potential threat.
        detectors_fired = sum(1 for r in results.values() if r.risk_score > 0)
        
        if detectors_fired >= 4:
            total_weighted_score *= 1.35   # 35% boost for 4+ signals
        elif detectors_fired >= 3:
            total_weighted_score *= 1.20   # 20% boost for 3 signals
        elif detectors_fired >= 2:
            total_weighted_score *= 1.10   # 10% boost for 2 signals

        # Final score calculation—rounded up to ensure even small threats are surfaced
        final_score = min(math.ceil(total_weighted_score), 100)
        
        # 4. Prepare the display order for the UI breakdown
        # We prioritize content and identity first as they are most readable for users.
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
            "trust_applied": False, # Trust dampening logic deactivated
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
            
        # High Confidence Override:
        # If any single detector is extremely confident (>=60) and the score is non-trivial (>=25),
        # we escalate the verdict to SUSPICIOUS even if the total weighted score is low.
        high_confidence_hit = any(r.risk_score >= 60 for r in results.values())
        if high_confidence_hit and score >= 25:
            return "SUSPICIOUS"
            
        return "SAFE"