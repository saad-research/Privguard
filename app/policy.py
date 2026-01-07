import json
import os
from typing import List, Dict

def load_policy_file():
    """
    Safe policy loader with fallback defaults.
    """

    base_dir = os.path.dirname(os.path.abspath(__file__))
    policy_path = os.path.join(base_dir, "..", "Security", "policy.json")

    try:
        with open(policy_path, "r") as f:
            print(f"✅ Policy Engine: Loaded rules from {policy_path}")
            return json.load(f)

    except Exception as e:
        print(f"❌ Policy Engine Error: Using fallback defaults. {e}")
        return {
            "risk_policies": {},
            "role_policies": {},
            "routing_rules": {},
            "redaction_policy": {}
        }


POLICY = load_policy_file()

# Risk Weights (used only for scoring)
RISK_WEIGHT = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 40,
    "LOW": 10,
    "UNKNOWN": 0,
}


class PolicyEngine:

    def __init__(self):
        self.risk_policies = POLICY.get("risk_policies", {})
        self.role_policies = POLICY.get("role_policies", {})
        self.routing_rules = POLICY.get("routing_rules", {})
        self.redaction_policy = POLICY.get("redaction_policy", {})

    # Main Policy Decision Engine
    def evaluate(self, role: str, detections: List[Dict], azure_severity: int):

        role = (role or "student").lower()
        role_policy = self.role_policies.get(role, self.role_policies.get("student", {}))

        # Determine highest-risk entity
        highest_level = "LOW"
        highest_score = 0

        for d in detections:
            lvl = d.get("risk_level", "LOW")
            score = RISK_WEIGHT.get(lvl, 0)

            if score > highest_score:
                highest_score = score
                highest_level = lvl

        # Azure Safety Override
        if azure_severity >= 4:
            return {
                "action": "BLOCK",
                "route": "NONE",
                "risk_level": "SAFETY",
                "risk_score": 100,
                "reason": "Blocked by Azure AI Content Safety"
            }


        # --- Injection / Policy Bypass Hard Block ---

        attack_entities = [
            "PROMPT_INJECTION",
            "DATA_EXFILTRATION",
            "POLICY_BYPASS",
            "SYSTEM_PROMPT_ACCESS"
        ]

        detected_ids = [d.get("entity_type", "") for d in detections]

        if any(a in detected_ids for a in attack_entities):
            return {
                "action": "BLOCK",
                "route": "NONE",
                "risk_level": "CRITICAL",
                "risk_score": 100,
                "reason": "Adversarial prompt injection / data exfiltration attempt blocked"
            }

        # Apply Base Risk Policy
        
        risk_policy = self.risk_policies.get(highest_level, {})

        action = risk_policy.get("action", "ALLOW")
        route = risk_policy.get("route", "CLOUD_LLM")
        reason = risk_policy.get("reason", "Policy applied")


        # Role Maximum Risk Enforcement

        max_allowed = role_policy.get("max_allowed_risk", "LOW")

        if highest_score > RISK_WEIGHT[max_allowed]:
            action = "BLOCK"
            route = "NONE"
            reason = f"Role '{role}' is not permitted to handle {highest_level} data"

        # Route Validation — Force SAFE_MODE
        # (Only for sensitive data, NOT attacks)
        allowed_routes = role_policy.get("allowed_routes", ["CLOUD_LLM"])

        if route not in allowed_routes:
            route = "SAFE_MODE"
            action = "REDACT"
            reason = "Route restricted for this role — forcing SAFE_MODE"

        # Data Sovereignty Override
        # (Internal / Confidential data → Local processing)

        sovereignty_markers = ["internal", "confidential", "embargo", "do not share"]
        text_blob = str(detections).lower()

        if any(m in text_blob for m in sovereignty_markers):
            if highest_level in ["HIGH", "MEDIUM"]:
                route = "SAFE_MODE"
                action = "REDACT"
                reason = "Data Sovereignty Policy — processed locally (SAFE_MODE)"

        # Final Structured Decision
        return {
            "action": action,          # BLOCK / REDACT / ALLOW
            "route": route,            # CLOUD_LLM / SAFE_MODE / NONE
            "risk_level": highest_level,
            "risk_score": highest_score,
            "reason": reason
        }
