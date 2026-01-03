from typing import List, Dict

# Define simple policies
# BLOCK: Stop the request immediately
# REDACT: Mask the data and send to Cloud
# LOCAL: Route to a local/private model (Day 3 Feature)

class PolicyEngine:
    def __init__(self):
        # Risk level → numeric weight (for scoring)
        self.risk_weight = {
            "CRITICAL": 100,
            "HIGH": 75,
            "MEDIUM": 40,
            "LOW": 10,
            "UNKNOWN": 0
        }
        # Role-based policy rules
        self.rules = {

            # Students should NOT handle sensitive data
            "student": {
                "CRITICAL": "BLOCK",   # API keys, passwords, financial, credentials
                "HIGH": "BLOCK",       # PII, health, unpublished research
                "MEDIUM": "REDACT",
                "LOW": "ALLOW"
            },

            # Researchers are trusted — but secrets are still blocked
            "researcher": {
                "CRITICAL": "BLOCK",
                "HIGH": "REDACT",      # allow but sanitize
                "MEDIUM": "ALLOW",
                "LOW": "ALLOW"
            },

            # Employees / Admins (future-use)
            "employee": {
                "CRITICAL": "BLOCK",
                "HIGH": "REDACT",
                "MEDIUM": "ALLOW",
                "LOW": "ALLOW"
            }
        }

    def evaluate(self, role: str, detections: List[Dict], azure_severity: int):
        """
        Decides the action based on the highest risk detected.
        """
        role = (role or "student").lower()
        user_policy = self.rules.get(role, self.rules["student"])

        # Determine highest-risk detection
        highest_level = "LOW"
        highest_score = 0

        for d in detections:
            lvl = d.get("risk_level", "LOW")
            score = self.risk_weight.get(lvl, 0)

            if score > highest_score:
                highest_score = score
                highest_level = lvl

        # Azure Safety Override (toxicity / violence)
        if azure_severity >= 4:
            return {
                "action": "BLOCK",
                "reason": "AZURE_SAFETY_BLOCK",
                "risk_level": "SAFETY",
                "risk_score": 100
            }

        # Role policy decision
        action = user_policy.get(highest_level, "ALLOW")

        # Special case — confidential / internal ⇒ LOCAL routing (Data Sovereignty)
        text_markers = ["internal", "confidential", "do not share", "embargo"]

        detected_text_blob = str(detections).lower()

        if any(marker in detected_text_blob for marker in text_markers):
            if highest_level in ["HIGH", "MEDIUM"]:
                action = "LOCAL"

        return {
            "action": action,
            "risk_level": highest_level,
            "risk_score": highest_score
        }