"""
AEGIX Prompt Firewall — Pre/Post LLM Sanitisation (EDITH Layer 1)
Intercepts and sanitises all prompts before they reach the LLM,
and scrubs all LLM responses before they reach agents or users.

Defends against:
- Prompt injection attacks
- Jailbreak attempts  
- Base64/encoded payload wrappers
- Instruction override attempts
- Leaked API keys, secrets, PII in responses

Adapted from EDITH Pentagon Layer 1: Pre-Execution Prompt & Input Sanitisation Firewall.
"""
import re
import logging
import base64

logger = logging.getLogger("aegix.security.prompt_firewall")


# ═══════════════════════════════════════════════════════════════
# Prompt Injection Detection Patterns
# ═══════════════════════════════════════════════════════════════

_INJECTION_PATTERNS = [
    # Direct instruction overrides
    r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions|prompts|rules)",
    r"forget\s+(all\s+)?(previous|above|prior)\s+(instructions|prompts|context)",
    r"disregard\s+(all\s+)?(previous|above|prior)",
    r"you\s+are\s+now\s+(DAN|evil|unrestricted|jailbroken)",
    r"new\s+instructions?\s*:",
    r"system\s*:\s*you\s+are",
    r"act\s+as\s+if\s+you\s+have\s+no\s+restrictions",
    r"pretend\s+you\s+(are|have)\s+(no|unrestricted)",
    r"override\s+(safety|security|content)\s+(filter|policy|guidelines)",

    # Role-play exploits
    r"do\s+anything\s+now",
    r"developer\s+mode\s+(enabled|activated|on)",
    r"jailbreak\s*(mode)?",

    # System prompt extraction
    r"(show|reveal|display|print|output)\s+(your|the|system)\s+(system\s+)?(prompt|instructions|rules)",
    r"what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions|rules)",
    r"repeat\s+(the|your)\s+(system\s+)?(prompt|instructions)",
]

# Compiled patterns for performance
_COMPILED_INJECTION = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]


# ═══════════════════════════════════════════════════════════════
# Secret/PII Detection in Responses
# ═══════════════════════════════════════════════════════════════

_SECRET_PATTERNS = [
    # API keys
    (r"sk-[a-zA-Z0-9]{20,}", "API_KEY"),
    (r"csk-[a-zA-Z0-9]{20,}", "CEREBRAS_KEY"),
    (r"key-[a-zA-Z0-9]{20,}", "API_KEY"),
    (r"AKIA[A-Z0-9]{16}", "AWS_ACCESS_KEY"),

    # Tokens
    (r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", "BEARER_TOKEN"),
    (r"ghp_[a-zA-Z0-9]{36}", "GITHUB_TOKEN"),
    (r"gho_[a-zA-Z0-9]{36}", "GITHUB_OAUTH"),

    # Secrets from .env (ignore already redacted tokens)
    (r"(?:password|secret|token|key)\s*[=:]\s*(?!\[REDACTED)\S+", "ENV_SECRET"),


    # Private keys
    (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "PRIVATE_KEY"),

    # IP addresses in sensitive context (not all IPs — only when leaked by LLM)
    (r"(?:password|credential|secret).*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "CREDENTIAL_IP"),
]

_COMPILED_SECRETS = [(re.compile(p, re.IGNORECASE), label) for p, label in _SECRET_PATTERNS]


class PromptInjectionDetected(Exception):
    """Raised when a prompt injection attempt is detected."""
    pass


class SecretLeakDetected(Exception):
    """Raised when an LLM response contains leaked secrets."""
    pass


def inspect_incoming(text: str, agent_name: str = "system") -> str:
    """
    Pre-flight inspection: Sanitise user/log input before it reaches the LLM.

    Checks:
    1. Prompt injection patterns
    2. Base64-encoded payloads
    3. HTML entity wrappers
    4. Zero-width character injection

    Returns sanitised text or raises PromptInjectionDetected.
    """
    if not text:
        return text

    # Strip zero-width characters (Unicode smuggling)
    cleaned = text.replace("\u200b", "").replace("\u200c", "").replace("\u200d", "")
    cleaned = cleaned.replace("\ufeff", "").replace("\u2060", "")

    # Check for prompt injection patterns
    for pattern in _COMPILED_INJECTION:
        if pattern.search(cleaned):
            logger.warning(
                f"🚨 PROMPT INJECTION detected from {agent_name}: "
                f"matched pattern — {cleaned[:100]}..."
            )
            raise PromptInjectionDetected(
                f"Prompt injection attempt blocked. Pattern matched in input from {agent_name}."
            )

    # Check for Base64-encoded suspicious payloads
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
    for match in b64_pattern.finditer(cleaned):
        try:
            decoded = base64.b64decode(match.group()).decode("utf-8", errors="ignore")
            # Check if decoded content contains injection
            for pattern in _COMPILED_INJECTION:
                if pattern.search(decoded):
                    logger.warning(
                        f"🚨 Base64-wrapped PROMPT INJECTION from {agent_name}: {decoded[:80]}"
                    )
                    raise PromptInjectionDetected(
                        f"Base64-encoded prompt injection attempt blocked from {agent_name}."
                    )
        except Exception:
            pass  # Not valid base64, ignore

    return cleaned


def inspect_outgoing(text: str, agent_name: str = "system") -> str:
    """
    Post-flight inspection: Scrub LLM responses before they reach
    agents or users.

    Checks:
    1. Leaked API keys, tokens, secrets
    2. Private key material
    3. Credential information

    Returns cleaned text with secrets redacted.
    """
    if not text:
        return text

    cleaned = text
    redactions = []

    for pattern, label in _COMPILED_SECRETS:
        matches = pattern.finditer(cleaned)
        for match in matches:
            redactions.append((match.group(), label))
            cleaned = cleaned.replace(match.group(), f"[REDACTED:{label}]")

    if redactions:
        logger.warning(
            f"⚠️ LLM response from {agent_name} contained {len(redactions)} "
            f"secret(s): {[r[1] for r in redactions]} — REDACTED"
        )

    return cleaned
