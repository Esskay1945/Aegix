"""
AEGIX Memory — ChromaDB-backed Reinforcement Learning Long-Term Memory
The Brain's persistent memory that stores "Lessons Learned" from every
incident and retrieval for self-prompting.

The RL loop:
  1. Fixer takes action → Critic scores it (+1/-1)
  2. Brain stores the full incident context + score as a "Lesson"
  3. Next similar incident → Brain recalls past lessons via semantic search
  4. Brain self-prompts agents based on past successes/failures

This is what makes the system LEARN. Without this, it's just a script.
"""
import json
import time
import hashlib
import logging
from typing import Optional
from pathlib import Path
from config import settings

logger = logging.getLogger("aegix.memory")

# Chroma client and collection globals
_chroma_client = None
_collection = None

# Fallback in-memory/JSON storage if ChromaDB is unavailable
_fallback_store = []
_fallback_file = Path(settings.CHROMA_PERSIST_DIR) / "memory_fallback.json"



def _load_fallback():
    global _fallback_store
    if _fallback_file.exists():
        try:
            with open(_fallback_file, "r", encoding="utf-8") as f:
                _fallback_store = json.load(f)
        except Exception:
            _fallback_store = []


def _save_fallback():
    try:
        _fallback_file.parent.mkdir(parents=True, exist_ok=True)
        with open(_fallback_file, "w", encoding="utf-8") as f:
            json.dump(_fallback_store, f, indent=2)
    except Exception as e:
        logger.warning(f"Failed to persist fallback memory: {e}")


def _get_collection():
    """Lazy-initialize ChromaDB collection with fallback."""
    global _chroma_client, _collection
    if _collection is not None:
        return _collection

    try:
        import chromadb
        from chromadb.config import Settings as ChromaSettings

        persist_dir = Path(settings.CHROMA_PERSIST_DIR)
        persist_dir.mkdir(parents=True, exist_ok=True)

        _chroma_client = chromadb.PersistentClient(
            path=str(persist_dir),
            settings=ChromaSettings(anonymized_telemetry=False),
        )
        _collection = _chroma_client.get_or_create_collection(
            name="aegix_memory",
            metadata={"description": "AEGIX RL Long-Term Memory — Lessons Learned"},
        )
        logger.info(
            f"ChromaDB memory initialized at {persist_dir} "
            f"({_collection.count()} lessons stored)"
        )
        return _collection
    except Exception as e:
        logger.warning(f"ChromaDB unavailable ({e}) — using persistent JSON memory store")
        _load_fallback()
        return None



def store_lesson(
    incident_summary: str,
    action_taken: str,
    critic_score: int,
    agent_name: str,
    metadata: dict = None,
) -> str:
    """
    Store a "Lesson Learned" into long-term memory.

    Args:
        incident_summary: Description of what happened (the threat/anomaly)
        action_taken: What The Fixer did about it
        critic_score: +1 (success) or -1 (failure/false positive)
        agent_name: Which agent was primarily involved
        metadata: Additional context (IPs, ports, attack type, etc.)

    Returns:
        lesson_id: Unique ID for this lesson
    """
    collection = _get_collection()

    lesson_id = hashlib.sha256(
        f"{incident_summary}:{action_taken}:{time.time()}".encode()
    ).hexdigest()[:16]

    lesson_text = (
        f"INCIDENT: {incident_summary}\n"
        f"ACTION: {action_taken}\n"
        f"OUTCOME: {'SUCCESS' if critic_score > 0 else 'FAILURE'}\n"
        f"SCORE: {critic_score}\n"
        f"AGENT: {agent_name}"
    )

    lesson_metadata = {
        "incident_summary": incident_summary[:500],
        "action_taken": action_taken[:500],
        "critic_score": critic_score,
        "agent_name": agent_name,
        "timestamp": time.time(),
        "outcome": "success" if critic_score > 0 else "failure",
    }
    if metadata:
        for k, v in metadata.items():
            if isinstance(v, (str, int, float, bool)):
                lesson_metadata[k] = v

    if collection is not None:
        collection.add(
            ids=[lesson_id],
            documents=[lesson_text],
            metadatas=[lesson_metadata],
        )
    else:
        _fallback_store.append({
            "id": lesson_id,
            "document": lesson_text,
            "metadata": lesson_metadata,
        })
        _save_fallback()

    logger.info(
        f"Stored lesson [{lesson_id}]: "
        f"{'✓ SUCCESS' if critic_score > 0 else '✗ FAILURE'} — {incident_summary[:80]}"
    )
    return lesson_id


def recall_similar(
    event_description: str,
    top_k: int = 5,
) -> list:
    """
    Recall past similar incidents from memory via semantic search.
    Returns list of past lessons ranked by similarity.

    Used by the Brain to self-prompt: "Have we seen this before?"
    """
    collection = _get_collection()

    if collection is not None:
        if collection.count() == 0:
            return []

        results = collection.query(
            query_texts=[event_description],
            n_results=min(top_k, collection.count()),
        )

        lessons = []
        if results and results["documents"]:
            for i, doc in enumerate(results["documents"][0]):
                meta = results["metadatas"][0][i] if results["metadatas"] else {}
                distance = results["distances"][0][i] if results["distances"] else 0.0
                lessons.append({
                    "id": results["ids"][0][i],
                    "document": doc,
                    "metadata": meta,
                    "similarity": max(0.0, 1.0 - distance),
                    "critic_score": meta.get("critic_score", 0),
                    "outcome": meta.get("outcome", "unknown"),
                })
        return lessons
    else:
        # Fallback word-overlap matching
        if not _fallback_store:
            return []
        query_words = set(event_description.lower().split())
        scored = []
        for item in _fallback_store:
            doc_words = set(item["document"].lower().split())
            overlap = len(query_words.intersection(doc_words)) / max(1, len(query_words))
            scored.append({
                "id": item["id"],
                "document": item["document"],
                "metadata": item["metadata"],
                "similarity": overlap,
                "critic_score": item["metadata"].get("critic_score", 0),
                "outcome": item["metadata"].get("outcome", "unknown"),
            })
        scored.sort(key=lambda x: x["similarity"], reverse=True)
        return scored[:top_k]


def get_success_patterns(top_k: int = 10) -> list:
    """Retrieve top successful (+1) past actions."""
    collection = _get_collection()

    if collection is not None:
        if collection.count() == 0:
            return []

        results = collection.get(
            where={"critic_score": 1},
            limit=top_k,
        )

        patterns = []
        if results and results["documents"]:
            for i, doc in enumerate(results["documents"]):
                patterns.append({
                    "id": results["ids"][i],
                    "document": doc,
                    "metadata": results["metadatas"][i] if results["metadatas"] else {},
                })
        return patterns
    else:
        return [
            item for item in _fallback_store
            if item.get("metadata", {}).get("critic_score") == 1
        ][:top_k]


def get_failure_patterns(top_k: int = 10) -> list:
    """Retrieve top failed (-1) past actions — mistakes to avoid."""
    collection = _get_collection()

    if collection is not None:
        if collection.count() == 0:
            return []

        results = collection.get(
            where={"critic_score": -1},
            limit=top_k,
        )

        patterns = []
        if results and results["documents"]:
            for i, doc in enumerate(results["documents"]):
                patterns.append({
                    "id": results["ids"][i],
                    "document": doc,
                    "metadata": results["metadatas"][i] if results["metadatas"] else {},
                })
        return patterns
    else:
        return [
            item for item in _fallback_store
            if item.get("metadata", {}).get("critic_score") == -1
        ][:top_k]


def generate_memory_context(event_description: str, max_lessons: int = 3) -> str:
    """
    Generate a memory context block for agent prompt injection.
    Called by the Overlord before dispatching to agents.

    Returns a formatted string with past relevant experiences.
    """
    lessons = recall_similar(event_description, top_k=max_lessons)

    if not lessons:
        return (
            "=== MEMORY CONTEXT ===\n"
            "No prior similar incidents found in memory. "
            "This may be a novel threat — proceed with full investigation.\n"
            "=== END MEMORY ===\n"
        )

    context_lines = ["=== MEMORY CONTEXT — PAST RELEVANT INCIDENTS ===\n"]
    for i, lesson in enumerate(lessons, 1):
        score = lesson["critic_score"]
        outcome = "✓ SUCCESSFUL" if score > 0 else "✗ FAILED"
        context_lines.append(
            f"[Lesson {i}] ({outcome}, similarity={lesson['similarity']:.2f}):\n"
            f"{lesson['document']}\n"
        )

        if score > 0:
            context_lines.append(
                "→ RECOMMENDATION: This approach worked before. "
                "Consider applying the same action for faster resolution.\n"
            )
        else:
            context_lines.append(
                "→ WARNING: This approach FAILED before. "
                "Do NOT repeat the same action. Find an alternative.\n"
            )

    context_lines.append("=== END MEMORY ===\n")
    return "\n".join(context_lines)


def get_memory_stats() -> dict:
    """Get memory statistics for dashboard/debug."""
    try:
        collection = _get_collection()
        if collection is not None:
            return {
                "engine": "ChromaDB",
                "total_lessons": collection.count(),
                "success_count": len(get_success_patterns(100)),
                "failure_count": len(get_failure_patterns(100)),
                "persist_dir": settings.CHROMA_PERSIST_DIR,
                "status": "ACTIVE",
            }
        else:
            return {
                "engine": "JSON Persistent Store",
                "total_lessons": len(_fallback_store),
                "success_count": len(get_success_patterns(100)),
                "failure_count": len(get_failure_patterns(100)),
                "persist_dir": settings.CHROMA_PERSIST_DIR,
                "status": "ACTIVE",
            }
    except Exception as e:
        return {"status": "ERROR", "error": str(e)}

