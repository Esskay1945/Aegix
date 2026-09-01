"""
AEGIX Identity — HMAC Agent Authentication (EDITH Layer 0)
Every inter-agent message is signed and verified via HMAC-SHA256.
Prevents agent impersonation and replay attacks.

Adapted from EDITH Pentagon Layer 0: Mutual Agent Authentication.
"""
import hmac
import hashlib
import time
import json
import logging
from typing import Optional
from config import settings

logger = logging.getLogger("aegix.security.identity")

# Agent registry — maps agent names to their secret keys
# In production, these would be rotated and stored securely
_agent_keys: dict = {}

# TTL for tokens (seconds)
TOKEN_TTL = 300  # 5 minutes
MIN_TTL = 1      # Minimum TTL floor (prevents zero-TTL race)


def register_agent(agent_name: str, secret_key: str = None) -> str:
    """
    Register an agent and assign it a unique secret key.
    Called during Brain boot-up for each agent.
    Returns the assigned key.
    """
    if secret_key is None:
        # Derive agent-specific key from master secret + agent name
        secret_key = hmac.new(
            settings.AGENT_SECRET_KEY.encode(),
            agent_name.encode(),
            hashlib.sha256,
        ).hexdigest()

    _agent_keys[agent_name] = secret_key
    logger.info(f"Agent '{agent_name}' registered with identity key")
    return secret_key


def sign_message(
    sender: str,
    recipient: str,
    payload: dict,
    ttl: int = TOKEN_TTL,
) -> dict:
    """
    Sign an inter-agent message with HMAC-SHA256.

    Returns a signed message envelope containing:
    - sender, recipient, payload, timestamp, ttl, signature
    """
    if sender not in _agent_keys:
        raise PermissionError(f"Agent '{sender}' not registered — cannot sign messages")

    ttl = max(ttl, MIN_TTL)  # Enforce minimum TTL floor
    timestamp = time.time()

    # Create the signing payload
    sign_data = json.dumps({
        "sender": sender,
        "recipient": recipient,
        "payload": payload,
        "timestamp": timestamp,
        "ttl": ttl,
    }, sort_keys=True)

    signature = hmac.new(
        _agent_keys[sender].encode(),
        sign_data.encode(),
        hashlib.sha256,
    ).hexdigest()

    return {
        "sender": sender,
        "recipient": recipient,
        "payload": payload,
        "timestamp": timestamp,
        "ttl": ttl,
        "signature": signature,
    }


def verify_message(message: dict) -> bool:
    """
    Verify an inter-agent message signature and TTL.

    Checks:
    1. Sender is registered
    2. Signature is valid (HMAC-SHA256)
    3. Message has not expired (TTL check)

    Raises PermissionError on verification failure.
    """
    sender = message.get("sender", "")
    if sender not in _agent_keys:
        raise PermissionError(f"Unknown sender: '{sender}' — message rejected")

    # Check TTL expiry
    timestamp = message.get("timestamp", 0)
    ttl = message.get("ttl", TOKEN_TTL)
    if time.time() - timestamp > ttl:
        raise PermissionError(
            f"Message from '{sender}' expired "
            f"(age={time.time() - timestamp:.1f}s, ttl={ttl}s)"
        )

    # Reconstruct and verify signature
    sign_data = json.dumps({
        "sender": sender,
        "recipient": message.get("recipient", ""),
        "payload": message.get("payload", {}),
        "timestamp": timestamp,
        "ttl": ttl,
    }, sort_keys=True)

    expected_signature = hmac.new(
        _agent_keys[sender].encode(),
        sign_data.encode(),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(message.get("signature", ""), expected_signature):
        raise PermissionError(f"Invalid signature from '{sender}' — message tampered or forged")

    logger.debug(f"Message from '{sender}' → '{message.get('recipient', '')}' verified ✓")
    return True


def get_registered_agents() -> list:
    """List all registered agent names."""
    return list(_agent_keys.keys())
