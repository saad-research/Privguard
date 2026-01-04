# PrivGuard — AI Privacy & Security Gateway

## Overview

**PrivGuard is a privacy and security gateway for Large Language Models (LLMs).**

It prevents sensitive university, research, and enterprise data from being exposed to public AI models by acting as a **middleware proxy** between users and external LLM APIs (e.g., OpenAI, Azure OpenAI).

PrivGuard inspects prompts in real time, detects sensitive content, applies role-based security policies, and enforces appropriate actions before any data reaches an external model.

In essence, **PrivGuard functions as a firewall for the LLM era**.

---

## Problem Statement

Students, researchers, and employees frequently paste sensitive content into AI tools such as ChatGPT, Copilot, or Gemini without understanding the privacy implications. This includes:

* Unpublished research drafts and papers under embargo
* Student records, transcripts, and identifiers
* Confidential or NDA-protected documents
* Cloud credentials, API keys, and secrets

Such behavior can:

* Violate institutional privacy and compliance policies
* Expose intellectual property (IP) to third-party systems
* Cause irreversible data leakage

**PrivGuard introduces a mandatory security checkpoint before any AI interaction occurs.**

---

## Core Capabilities

PrivGuard enforces security controls in real time:

* **Block** high-risk requests (credentials, secrets, critical PII)
* **Redact** sensitive fields before forwarding requests
* **Route** sensitive content to a secure local or on-premise LLM (data sovereignty mode)
* **Allow** low-risk requests to proceed to cloud-based LLMs

---

## How PrivGuard Works

Every prompt passes through a three-stage security pipeline.

### 1. Sensitive Data Detection

PrivGuard combines **Microsoft Presidio** with custom regular-expression rules to detect:

* **PII**: Emails, phone numbers, addresses, dates of birth
* **Academic Data**: Student IDs, transcripts, unpublished research
* **Secrets**: API keys, access tokens, passwords, private keys
* **Enterprise Data**: Confidential markers, financial identifiers
* **Abuse Patterns**: Prompt injection and data exfiltration attempts

Detection rules are defined in `security/patterns.json` and loaded dynamically by the detection engine.

---

### 2. Risk-Aware Policy Engine (RBAC)

Detected entities are evaluated using a **risk-aware, role-based policy engine**. Each detection is tagged with a risk level (LOW, MEDIUM, HIGH, CRITICAL), and the highest-risk signal determines enforcement behavior.

Policies are:

* declaratively defined in `security/policy.json`
* enforced centrally by a Python-based policy engine
* configurable without backend code changes

The policy engine supports:

* role-based access control (RBAC)
* risk scoring and prioritization
* default-deny / fail-safe behavior

---

### 3. Smart Routing and Data Sovereignty

PrivGuard dynamically routes requests based on risk level and policy:

| Data Type                         | User Role  | Action      | Destination      |
| --------------------------------- | ---------- | ----------- | ---------------- |
| API keys / credentials            | Any        | Block       | Request rejected |
| Internal or confidential research | Researcher | Route local | On-prem LLM      |
| PII (email, phone)                | Student    | Block       | Request rejected |
| PII (email, phone)                | Researcher | Redact      | Cloud LLM        |
| Low-risk content                  | Any        | Allow       | Cloud LLM        |

This ensures sensitive data never leaves institutional boundaries.

---

## Architecture (MVP)

```
User Prompt
   → PrivGuard Proxy
   → Detection Engine
   → Policy Engine
   → { BLOCK | REDACT | LOCAL | CLOUD }
```
### Architecture Diagram

![Architecture](Architecture/architect_priv1.png)


PrivGuard is middleware infrastructure, not an end-user chatbot.

---

## Example Scenarios

### Student submits API key

Result: Request blocked

```json
{
  "status": "blocked",
  "action": "BLOCKED_BY_POLICY",
  "risk_level": "CRITICAL",
  "message": "Request blocked due to security policy."
}
```

---

### Researcher submits email address

Result: Redaction and cloud routing

Input:

```
Contact me at jane@uni.edu
```

Output:

```
Contact me at [REDACTED:EMAIL]
```

The sanitized prompt is forwarded to Azure OpenAI.

---

### Confidential research content

Result: Local routing

Input:

```
CONFIDENTIAL: Draft patent filing for...
```

Output:

```
Processed locally. No data sent to cloud LLM.
```

---

## Technology Stack

* FastAPI — High-performance asynchronous API gateway
* Microsoft Presidio — NLP-based PII detection
* spaCy (`en_core_web_md`) — Entity recognition
* Custom Regex Engine — Domain-specific pattern detection
* Python Policy Engine — Role-based access and routing decisions
* Azure AI Content Safety — Upstream safety moderation

---

## Roadmap

### Phase 1 — Core Engine (Completed)

* Detection layer (Regex + NLP)
* Risk-aware policy engine (Block / Redact / Route)
* API gateway implementation

### Phase 2 — Enterprise Features (In Progress)

* Tamper-evident audit logs (hash chaining)
* Security dashboard (risk trends, attack visibility)
* Streamlit demo UI (before / after enforcement)
* Automated attack simulation (`attacks.csv`)
* Policy visualization and approval workflows

---

## Project Roles

### Dev Lead

* Gateway architecture and API orchestration
* Hybrid routing engine (Cloud → Safe Mode → Local LLM)
* Redaction & sanitization pipeline implementation
* Policy engine integration and risk-based enforcement logic
* Design of RBAC execution behavior and escalation thresholds
* Data sovereignty execution model (routing guarantees)
* System reliability, testing, and behavior validation

### Security Lead

* Threat modeling and attack surface analysis
* Sensitive data taxonomy and detection rules (`patterns.json`)
* Risk classification and policy specification
* Role-based access control (RBAC) policy rules (`policy.json`)
* Data handling principles and routing justification
* Privacy-preserving audit logging strategy
* Red-team prompt design and abuse simulation

---

## License

MIT License

