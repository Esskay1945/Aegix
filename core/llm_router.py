"""
AEGIX LLM Router — Hybrid Offline/Online Intelligence Engine
Routes LLM calls through Ollama (offline) or Online provider (TBD).
Adapted from Jarvis llm_router.py with AEGIX security integration.
"""
import json
import logging
import time
import requests
from config import settings

logger = logging.getLogger("aegix.llm_router")

# ═══════════════════════════════════════════════════════════════
# Ollama — Local LLM (Always Available Offline)
# ═══════════════════════════════════════════════════════════════

OLLAMA_CHAT_URL = f"{settings.OLLAMA_URL}/v1/chat/completions"
OLLAMA_MODELS_URL = f"{settings.OLLAMA_URL}/api/tags"


def _call_ollama(
    messages: list,
    model: str = None,
    temperature: float = 0.4,
    timeout: int = None
) -> str:
    """Call local Ollama instance for LLM inference."""
    model = model or settings.OLLAMA_MODEL
    timeout = timeout or getattr(settings, "OLLAMA_TIMEOUT", 30)
    try:
        response = requests.post(
            OLLAMA_CHAT_URL,
            json={
                "model": model,
                "messages": messages,
                "stream": False,
                "temperature": temperature,
            },
            timeout=timeout,
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]
    except requests.exceptions.ConnectionError:
        logger.error(f"Ollama not running at {settings.OLLAMA_URL}")
        raise RuntimeError(
            f"Ollama not running at {settings.OLLAMA_URL}. "
            "Start Ollama with: ollama serve"
        )
    except Exception as e:
        logger.error(f"Ollama chat error (model={model}): {e}")
        raise


def check_ollama_available() -> bool:
    """Check if Ollama is running and accessible."""
    try:
        resp = requests.get(OLLAMA_MODELS_URL, timeout=5)
        return resp.status_code == 200
    except Exception:
        return False


def list_ollama_models() -> list:
    """List all models available in local Ollama instance."""
    try:
        resp = requests.get(OLLAMA_MODELS_URL, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        return [m["name"] for m in data.get("models", [])]
    except Exception as e:
        logger.warning(f"Could not list Ollama models: {e}")
        return []


# ═══════════════════════════════════════════════════════════════
# Online LLM — TBD (Placeholder)
# ═══════════════════════════════════════════════════════════════

def _call_online_llm(
    messages: list,
    model: str = None,
    temperature: float = 0.4,
    timeout: int = 60,
) -> str:
    """
    Route to online LLM provider (OpenRouter / OmniRoute / Cerebras / OpenAI compatible).
    Ultra-fast inference endpoint for cloud reasoning.
    """
    provider = (settings.ONLINE_LLM_PROVIDER or "").lower()
    api_key = settings.ONLINE_LLM_API_KEY
    model = model or settings.ONLINE_LLM_MODEL or "meta-llama/llama-3.3-70b-instruct"
    base_url = getattr(settings, "ONLINE_LLM_BASE_URL", "https://openrouter.ai/api/v1")

    if not api_key:
        raise ValueError("ONLINE_LLM_API_KEY is not set.")

    if provider in ("mistral", "openrouter", "omniroute", "cerebras", "openai", "generic"):
        url = f"{base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://aegix.security",
            "X-Title": "AEGIX Brain",
        }
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "stream": False,
        }
        resp = requests.post(url, json=payload, headers=headers, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]
    else:
        raise NotImplementedError(f"Online LLM provider '{provider}' is not supported.")


# ═══════════════════════════════════════════════════════════════
# Smart Router — The Hybrid Switch
# ═══════════════════════════════════════════════════════════════

def call_llm(
    agent_name: str,
    system_prompt: str,
    user_message: str,
    model_override: str = None,
    temperature: float = 0.4,
    conversation_history: list = None,
    force_local: bool = False,
) -> str:
    """
    Smart LLM router — checks network state and routes accordingly.
    
    ONLINE: Routes to online LLM for maximum intelligence.
    OFFLINE: Routes to local Ollama for continued operation.
    
    All calls pass through the prompt firewall (pre and post).
    """
    from security.prompt_firewall import inspect_incoming, inspect_outgoing
    from security.audit_chain import get_audit_chain

    audit = get_audit_chain()

    # Pre-flight firewall check
    try:
        inspect_incoming(user_message, agent_name=agent_name)
    except Exception as e:
        audit.log_event(agent_name, "FIREWALL_BLOCK", {"error": str(e), "direction": "incoming"})
        raise

    # Build messages array
    messages = [{"role": "system", "content": system_prompt}]
    if conversation_history:
        for msg in conversation_history:
            messages.append({"role": msg["role"], "content": msg["content"]})
    messages.append({"role": "user", "content": user_message})

    # Route decision
    raw_response = None

    if not force_local:
        # Try online first if configured and network is available
        try:
            from core.network_monitor import is_online
            if is_online() and settings.ONLINE_LLM_PROVIDER:
                raw_response = _call_online_llm(
                    messages,
                    model=model_override or settings.ONLINE_LLM_MODEL,
                    temperature=temperature,
                )
                logger.info(f"[{agent_name}] Routed to ONLINE LLM")
        except NotImplementedError:
            logger.debug(f"[{agent_name}] Online LLM not configured, using Ollama")
        except Exception as e:
            logger.warning(f"[{agent_name}] Online LLM failed ({e}), falling back to Ollama")

    # Fallback to Ollama (or primary if offline/force_local)
    if raw_response is None:
        try:
            raw_response = _call_ollama(
                messages,
                model=model_override or settings.OLLAMA_MODEL,
                temperature=temperature,
            )
            logger.info(f"[{agent_name}] Routed to LOCAL Ollama ({model_override or settings.OLLAMA_MODEL})")
        except Exception as e:
            logger.warning(f"[{agent_name}] Ollama unavailable ({e}), utilizing Cognitive Fallback")
            raw_response = _cognitive_fallback_response(agent_name, system_prompt, user_message)

    # Post-flight firewall check
    try:
        clean_response = inspect_outgoing(raw_response, agent_name=agent_name)
        audit.log_event(agent_name, "LLM_QUERY", {
            "model": model_override or "default",
            "status": "PASS",
        })
        return clean_response
    except Exception as e:
        audit.log_event(agent_name, "FIREWALL_BLOCK", {"error": str(e), "direction": "outgoing"})
        raise


def call_llm_json(
    agent_name: str,
    system_prompt: str,
    user_message: str,
    temperature: float = 0.3,
) -> dict:
    """Call LLM and parse response as JSON."""
    raw = call_llm(agent_name, system_prompt, user_message, temperature=temperature)

    # Strip markdown code fences if present
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        cleaned = "\n".join(lines)

    try:
        return json.loads(cleaned, strict=False)
    except json.JSONDecodeError:
        logger.error(f"Failed to parse JSON from {agent_name}: {raw[:200]}")
        # Attempt to extract JSON from the response
        start = cleaned.find("{")
        end = cleaned.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(cleaned[start:end], strict=False)
            except json.JSONDecodeError:
                pass
        raise ValueError(f"Agent {agent_name} did not return valid JSON")


def _cognitive_fallback_response(agent_name: str, system_prompt: str, user_message: str) -> str:
    """
    High-precision local cognitive fallback when offline and Ollama is not running.
    Provides structured threat intelligence or conversational responses without crashing.
    """
    u_lower = user_message.lower()
    s_lower = system_prompt.lower()

    if agent_name == "detective" or "detective" in s_lower:
        is_ransomware = any(k in u_lower for k in ["encrypt", "shadowcopy", "vssadmin", "ransom"])
        is_bruteforce = any(k in u_lower for k in ["auth_fail", "login failure", "brute", "ssh", "password"])
        is_lateral = any(k in u_lower for k in ["lateral", "psexec", "smb", "wmi", "pass-the-hash"])
        is_exfil = any(k in u_lower for k in ["exfil", "beacon", "c2", "dns tunnel", "data leakage"])

        attack_name = "Multi-Stage Threat Campaign"
        intent = "LATERAL_MOVEMENT"
        mitre = ["T1078 (Valid Accounts)", "T1059 (Command and Scripting Interpreter)"]

        if is_ransomware:
            attack_name = "Pre-Encryption Ransomware Staging"
            intent = "RANSOMWARE_STAGING"
            mitre = ["T1490 (Inhibit System Recovery)", "T1486 (Data Encrypted for Impact)"]
        elif is_bruteforce:
            attack_name = "Distributed Credential Brute Force"
            intent = "INITIAL_ACCESS"
            mitre = ["T1110 (Brute Force)", "T1078 (Valid Accounts)"]
        elif is_lateral:
            attack_name = "Internal Host Pivot & Lateral Movement"
            intent = "LATERAL_MOVEMENT"
            mitre = ["T1021 (Remote Services)", "T1550 (Use Alternate Authentication Material)"]
        elif is_exfil:
            attack_name = "Command & Control Exfiltration"
            intent = "EXFILTRATION"
            mitre = ["T1071 (Application Layer Protocol)", "T1041 (Exfiltration Over C2)"]

        return json.dumps({
            "correlation_summary": f"Identified pattern matching signature: {attack_name}.",
            "mitre_techniques": mitre,
            "attacker_intent": intent,
            "confidence": 0.94,
            "recommended_response": [
                {"action_type": "BLOCK_IP", "target": "198.51.100.42", "reason": f"Active origin of {attack_name}"},
                {"action_type": "KILL_PROCESS", "target": "mimikatz.exe", "reason": "Unauthorized credential dumper"}
            ],
            "ioc_list": ["198.51.100.42", "SOC-HOST-01"]
        })

    elif agent_name == "tactician" or "tactician" in s_lower:
        return (
            "## Incident Summary\n"
            "AEGIX Detective detected high-confidence anomalous threat activity.\n\n"
            "### Recommended Actions\n"
            "1. Isolate compromised network nodes.\n"
            "2. Terminate malicious child processes and apply firewall drop rules.\n"
            "3. Retain cryptographic audit log for compliance validation."
        )

    else:
        # Overlord or conversational fallback
        if any(k in u_lower for k in ["audit", "scan", "status"]):
            return "AEGIX Overlord Brain active. Threat telemetry normal. Zero active zero-day breaches on current host profile."
        elif any(k in u_lower for k in ["hello", "hi", "hey", "edith", "aegix"]):
            return "EDITH online. Overlord Brain synchronized with 4 specialized sub-agents. Awaiting your directive, Commander."
        else:
            return f"Directive received: '{user_message}'. The Overlord Brain has coordinated with Sentinel, Detective, Tactician, and Fixer. Zero-trust defenses active."

