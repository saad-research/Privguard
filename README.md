# 🛡️ PRIVGUARD — AI Privacy & Security Gateway

**PrivGuard is a Firewall for the LLM Era.**

It prevents sensitive university, research, and enterprise data from leaking into public AI models by acting as a **smart proxy gateway** between users and LLMs.

PrivGuard inspects prompts, detects sensitive content, applies role-based security policies, and acts in real-time to:

✔ **Block** risky requests (e.g., API Keys, PII)  
✔ **Redact** sensitive fields automatically  
✔ **Route** data to a secure **Local / On-Prem LLM** (Data Sovereignty Mode)  
✔ **Allow** safe requests to Cloud LLMs (Azure/OpenAI)

---

## 🎯 The Core Problem

Students and researchers often paste:
* Internal research drafts
* Unpublished papers (under embargo)
* Student records & transcripts
* Cloud Credentials & API keys
* Confidential / NDA documents

...into ChatGPT, Gemini, or Copilot without realizing they may:
❌ Violate institutional privacy policies  
❌ Expose intellectual property (IP) to external training data  
❌ Cause accidental data leaks

**PrivGuard acts as the security layer in-between.**

---

## ⚙️ How It Works

PrivGuard performs a 3-step security check on every prompt:

### 🧠 1. Sensitive Data Detection (Regex + NLP)
Using **Microsoft Presidio** + custom Security Patterns, we detect:
* **PII:** Emails, phone numbers, addresses
* **Academic:** Student IDs, transcripts, unpublished research
* **Secrets:** API keys (`sk-...`, `ghp_...`), passwords, private keys
* **Enterprise:** Confidential markers, financial data
* **Attacks:** Prompt injection attempts

*Patterns are defined in `Security/patterns.json`.*

### 🛡️ 2. Risk-Aware Policy Engine (RBAC)
Policies are applied based on the user's role:
* **Student:** Untrusted. strict blocking of PII and Secrets.
* **Researcher:** Semi-trusted. PII is redacted; Secrets are blocked.
* **Employee/Admin:** Custom handling.

### 🔀 3. Smart Routing (Hybrid Cloud + Local)
PrivGuard enforces Data Sovereignty by routing traffic dynamically:

| Data Type | User Role | Action | Destination |
| :--- | :--- | :--- | :--- |
| **API Keys / Secrets** | *Any* | **BLOCK** 🚫 | None (Request Rejected) |
| **"Internal" Research** | Researcher | **ROUTE LOCAL** 🔒 | Local On-Prem LLM |
| **PII (Email/Phone)** | Student | **BLOCK** 🚫 | None |
| **PII (Email/Phone)** | Researcher | **REDACT** ✂️ | Cloud LLM (Sanitized) |
| **Safe Content** | *Any* | **ALLOW** ✅ | Azure OpenAI / Cloud |

---

## 🧩 Architecture (MVP)

User Prompt → PrivGuard Proxy → Detection Engine → Policy Engine → ( BLOCK | REDACT | LOCAL | CLOUD )

---

## 🧪 Example Behaviors

### 1) Student pastes API Key → BLOCKED

```json
{
  "status": "blocked",
  "action": "BLOCKED_BY_POLICY",
  "risk_level": "CRITICAL",
  "message": "Request blocked due to security policy."
}
```
### 2) Researcher pastes Email → REDACT + CLOUD

Input: "Contact me at jane@uni.edu"

Output: "Contact me at [REDACTED:EMAIL]"

(Sent safely to Azure OpenAI)

### 3) Internal Research → ROUTED LOCAL

Input: "CONFIDENTIAL: Draft patent filing for..."

Output: [LOCAL] Processed on-prem. No data left the network.

## 🏗 Tech Stack

- FastAPI (High-performance Async Gateway)

- Microsoft Presidio (NLP-based PII Detection)

- Spacy (en_core_web_md for entity recognition)

- Custom Regex Engine (Pattern matching for specific secrets)

- Role-Based Policy Engine (Python-based logic core)

- Azure AI Content Safety (Upstream toxicity checks)

---

## ▶ Running PrivGuard

1. Environment Setup
```
# Create virtual environment
python -m venv venv

# Activate (Mac/Linux)
source venv/bin/activate 
# Activate (Windows)
.\venv\Scripts\activate
```
2. Install Dependencies

```
pip install -r requirements.txt

# IMPORTANT: Download the NLP model
python -m spacy download en_core_web_md
```

3. Run the Gateway

```
uvicorn app.main:app --reload
```

The API will start at: http://127.0.0.1:8000

4. Explore the API

Open your browser to the interactive docs:

👉 http://127.0.0.1:8000/docs

---

##  Roadmap

Phase 1: Core Engine (Completed)

✅ Regex & NLP Detection Layer
✅ Policy Engine (Block/Redact/Route logic)
✅ API Gateway Implementation

Phase 2: Enterprise Features (In Progress)

-  Tamper-proof Audit Logs (SHA-256 Hashing)
-  Security Dashboard (attack report & risk stats)
-  Streamlit Demo UI (Before / After Privacy Mode)
-  Automated Attack Simulation (`attacks.csv`)
-  Policy visualization + approval flows

---

## 👥 Project Roles

Dev Lead — Gateway Architecture, Routing Logic, Core Engine  
Security Lead — Threat Intelligence, Regex Patterns, Policy Rules

---

##  License

MIT
