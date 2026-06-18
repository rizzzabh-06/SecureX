"""
RAG Memory Engine — Local vector database of past analyses.
Uses ChromaDB (embedded, no server) + SentenceTransformers (local, no API).
No internet needed. Runs entirely on your machine.
"""

import json
from typing import List, Optional

from app.config import settings


class MalwareRAG:
    """
    Local vector database of malware analysis features.
    Pre-load with known samples, then use similarity search
    to identify malware families on new APKs.
    """

    def __init__(self):
        self._client = None
        self._collection = None
        self._model = None
        self._initialized = False

    def _ensure_init(self):
        """Lazy initialization — only load heavy models when first needed."""
        if self._initialized:
            return

        try:
            import chromadb
            from sentence_transformers import SentenceTransformer

            self._client = chromadb.PersistentClient(path=settings.CHROMADB_DIR)
            self._collection = self._client.get_or_create_collection(
                name="malware_samples",
                metadata={"hnsw:space": "cosine"}
            )
            # 80MB model, runs locally, no API
            self._model = SentenceTransformer("all-MiniLM-L6-v2")
            self._initialized = True
            print(f"[RAG] Initialized with {self._collection.count()} samples")
        except ImportError as e:
            print(f"[RAG] Dependencies not installed: {e}")
        except Exception as e:
            print(f"[RAG] Init failed: {e}")

    def add_sample(self, sample_id: str, features: dict, label: str):
        """Add a known malware sample to the corpus."""
        self._ensure_init()
        if not self._initialized:
            return

        text = self._features_to_text(features)
        embedding = self._model.encode(text).tolist()
        self._collection.upsert(
            ids=[sample_id],
            embeddings=[embedding],
            documents=[text],
            metadatas=[{
                "label": label,
                "features": json.dumps(features)
            }]
        )

    def find_similar(self, features: dict, top_k: int = 3) -> list:
        """Find most similar historical samples to the given features."""
        self._ensure_init()
        if not self._initialized or self._collection.count() == 0:
            return []

        text = self._features_to_text(features)
        embedding = self._model.encode(text).tolist()

        results = self._collection.query(
            query_embeddings=[embedding],
            n_results=min(top_k, self._collection.count()),
            include=["metadatas", "distances"]
        )

        similar = []
        for i in range(len(results["ids"][0])):
            distance = results["distances"][0][i]
            similarity = round((1 - distance) * 100, 1)
            meta = results["metadatas"][0][i]
            similar.append({
                "label": meta.get("label", "unknown"),
                "similarity_pct": similarity,
                "match_strength": (
                    "HIGH" if similarity > 85 else
                    "MEDIUM" if similarity > 65 else
                    "LOW"
                )
            })

        return similar

    def _features_to_text(self, features: dict) -> str:
        """Serialize features to consistent text for embedding."""
        parts = []
        for key in ["permissions", "apis", "behaviors", "c2_patterns", "dangerous_permissions"]:
            vals = features.get(key, [])
            if vals:
                parts.append(f"{key}:{' '.join(str(v) for v in vals)}")
        return " ".join(parts) if parts else "unknown"

    def seed_from_malwarebazaar(self, count: int = 50):
        """
        Pre-load corpus from MalwareBazaar's free public API.
        Run once before the hackathon to populate the DB.
        """
        self._ensure_init()
        if not self._initialized:
            return

        import requests
        try:
            resp = requests.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_taginfo", "tag": "AndroidBanker", "limit": count},
                timeout=30
            )
            for sample in resp.json().get("data", []):
                self.add_sample(
                    sample_id=sample["sha256_hash"],
                    features={
                        "permissions": [],
                        "apis": [],
                        "behaviors": sample.get("tags", []),
                        "c2_patterns": []
                    },
                    label=sample.get("tags", ["unknown"])[0] if sample.get("tags") else "unknown"
                )
            print(f"[RAG] Seeded {count} samples from MalwareBazaar")
        except Exception as e:
            print(f"[RAG] Seeding failed: {e}")

    def get_count(self) -> int:
        """Get number of samples in the corpus."""
        self._ensure_init()
        if not self._initialized:
            return 0
        return self._collection.count()


# Singleton
rag_engine = MalwareRAG()
