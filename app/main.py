import hashlib
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from app.detector import analyze_text
from app.redactor import redact_text
from app.content_safety import check_content_risk
from app.policy import PolicyEngine
from Security import log_event

app = FastAPI(title="PrivGuard Core Gateway", version="0.2.0")
policy = PolicyEngine()

# Since, visiting "/" Returns 404 error
@app.get("/")
def index():
    return {"service": "PrivGuard Core Gateway", "status": "running"}


# Analyze Endpoint
class AnalyzeRequest(BaseModel):
    text: str

@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    entities = analyze_text(req.text)
    return {"entities": entities}

@app.get("/health")
def health_check():
    return {"status": "ok"}

# Redact Endpoint
class RedactRequest(BaseModel):
    text: str

@app.post("/redact")
def redact(req: RedactRequest):
    entities = analyze_text(req.text)
    redacted = redact_text(req.text, entities)
    return {
        "original_text": req.text,
        "entities": entities,
        "redacted_text": redacted
    }

# Proxy Endpoint
class ProxyRequest(BaseModel):
    text: str
    user_role: str = "Student"

@app.post("/proxy")
def proxy(req: ProxyRequest, x_user_role: str = Header(default="student")):
    try:
        effective_role = (x_user_role or req.user_role or "student").lower()
        
        # 1) AZURE SAFETY CHECK (toxicity / violence / abuse)
        azure_severity = check_content_risk(req.text)

        
        # 2) LOCAL PII / SECRET DETECTION
        detections = analyze_text(req.text)

        
        # 3) POLICY ENGINE — decides BLOCK / LOCAL / REDACT / ALLOW
        
        decision = policy.evaluate(
            role=effective_role,
            detections=detections,
            azure_severity=azure_severity
        )

        # 4) SECURITY AUDIT LOG (safe — never breaks API)

        try:
            request_hash = hashlib.sha256(req.text.encode()).hexdigest()

            matched_patterns = [
                d.get("entity_type", "UNKNOWN")
                for d in detections
            ]

            log_event(
                user_role=effective_role,
                detected_risk=decision["risk_level"],
                matched_patterns=matched_patterns,
                action_taken=decision["action"],
                routing_decision=decision.get("route", "UNKNOWN"),
                request_hash=request_hash,
                processing_latency_ms=None
            )

        except Exception as log_error:
            # Never interrupt gateway execution if logging fails
            print("⚠️ Audit log failed but request continued:", log_error)

        
        # 5) ENFORCEMENT
        

        # BLOCKED
        if decision["action"] == "BLOCK":
            return {
                "status": "blocked",
                "action": "BLOCKED_BY_POLICY",
                "risk_level": decision["risk_level"],
                "risk_score": decision["risk_score"],
                "message": decision.get("reason", "Request blocked due to security policy.")
            }

        # LOCAL / SAFE MODE
        if decision.get("route") == "SAFE_MODE" or decision["action"] == "LOCAL":
            sanitized = redact_text(req.text, detections)
            return {
                "status": "success",
                "action": "ROUTED_TO_LOCAL_MODEL",
                "risk_level": decision["risk_level"],
                "risk_score": decision["risk_score"],
                "sanitized_prompt": sanitized,
                "llm_response": "[LOCAL] Processed on-prem. No data left the network."
            }

        # CLOUD ROUTE (default)
        sanitized = redact_text(req.text, detections)
        return {
            "status": "success",
            "action": "ROUTED_TO_CLOUD_OPENAI",
            "risk_level": decision["risk_level"],
            "risk_score": decision["risk_score"],
            "entities_detected": detections,
            "sanitized_prompt": sanitized,
            "llm_response": "[CLOUD] Safe request processed via Azure OpenAI."
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
