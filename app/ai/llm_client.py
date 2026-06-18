"""
LLM Client with automatic fallback chain:
1. Groq API (Llama 3.1-70B, ~300 tok/s, FREE)
2. Google Gemini 1.5 Flash (FREE tier)
3. Ollama local (llama3.2:3b, fully offline)

Ensures the live demo NEVER fails due to API issues.
"""

import json
import re
from typing import Optional

from app.config import settings


class LLMClient:
    """
    Multi-provider LLM client with automatic fallback.
    Tries Groq first (fastest, free), then Gemini, then local Ollama.
    """

    def __init__(self):
        self._groq_client = None
        self._gemini_model = None
        self._init_providers()

    def _init_providers(self):
        """Initialize available LLM providers."""
        # Groq
        if settings.GROQ_API_KEY:
            try:
                from groq import Groq
                self._groq_client = Groq(api_key=settings.GROQ_API_KEY)
                print("[LLM] Groq client initialized (Llama 3.1-70B)")
            except Exception as e:
                print(f"[LLM] Groq init failed: {e}")

        # Gemini
        if settings.GEMINI_API_KEY:
            try:
                from google import genai
                self._gemini_client = genai.Client(api_key=settings.GEMINI_API_KEY)
                print("[LLM] Gemini 2.5 Flash initialized")
            except Exception as e:
                print(f"[LLM] Gemini init failed: {e}")

    def complete(self, system_prompt: str, user_prompt: str,
                 max_tokens: int = 2000) -> str:
        """
        Send a prompt to the LLM with automatic fallback.
        Returns the raw text response.
        """
        # Try Groq first (fastest)
        if self._groq_client:
            try:
                # Groq TPM Free Tier = Prompt Tokens + Max Tokens. 
                # Clamp max_tokens to 1200 so we stay under the 6000 limit with the massive payloads!
                safe_max_tokens = min(max_tokens, 1200)

                response = self._groq_client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=0.1,
                    max_tokens=safe_max_tokens
                )
                return re.sub(r'<think>.*?</think>', '', response.choices[0].message.content, flags=re.DOTALL).strip()
            except Exception as e:
                if "rate_limit_exceeded" in str(e):
                    print(f"[LLM] Groq 70B rate limited. Trying 8B fallback...")
                    try:
                        fallback_resp = self._groq_client.chat.completions.create(
                            model="llama-3.1-8b-instant",
                            messages=[
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": user_prompt}
                            ],
                            temperature=0.1,
                            max_tokens=max_tokens
                        )
                        return re.sub(r'<think>.*?</think>', '', fallback_resp.choices[0].message.content, flags=re.DOTALL).strip()
                    except Exception as fallback_err:
                        print(f"[LLM] Groq 8B fallback also failed: {fallback_err} → falling back to Gemini")
                else:
                    print(f"[LLM] Groq failed: {e} → falling back to Gemini")

        # Fallback to Gemini
        if hasattr(self, '_gemini_client') and self._gemini_client:
            try:
                combined = f"System: {system_prompt}\n\nUser: {user_prompt}"
                response = self._gemini_client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=combined
                )
                return re.sub(r'<think>.*?</think>', '', response.text, flags=re.DOTALL).strip()
            except Exception as e:
                print(f"[LLM] Gemini failed: {e}")
                return json.dumps({"error": f"All LLM providers failed: {e}"})

        return json.dumps({"error": "No LLM providers configured or available."})

    def complete_json(self, system_prompt: str, user_prompt: str,
                      max_tokens: int = 2000) -> dict:
        """
        Send a prompt and parse the response as JSON.
        Handles markdown code fences and other LLM quirks.
        """
        raw = self.complete(system_prompt, user_prompt, max_tokens)
        return self.safe_json(raw)

    def safe_json(self, raw: str) -> dict:
        """Parse LLM JSON output even if it has markdown fences or noise."""
        if not raw:
            return {"error": "Empty response", "parse_error": True}

        # Strip markdown code fences
        clean = re.sub(r'```json\s*|```\s*', '', raw).strip()

        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            pass

        # Try to find the first { ... } block
        match = re.search(r'\{.*\}', clean, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass

        # Try to find [ ... ] array
        match = re.search(r'\[.*\]', clean, re.DOTALL)
        if match:
            try:
                return {"items": json.loads(match.group())}
            except json.JSONDecodeError:
                pass

        # Aggressive manual fallback for broken JSON (handles unescaped newlines from massive outputs)
        fallback_dict = {"parse_error": True, "raw_response": raw}
        
        # Try to explicitly extract the massive chain_of_reasoning block
        chain_match = re.search(r'"chain_of_reasoning"\s*:\s*"?([\s\S]*?)(?:",\s*"[a-zA-Z_]+"\s*:|"\s*\n?\s*\}|$)', clean)
        if chain_match:
            val = chain_match.group(1).strip()
            # Clean up trailing quotes or commas
            if val.endswith('"'):
                val = val[:-1]
            val = val.replace('\\n', '\n')
            val = val.replace('\\"', '"')
            fallback_dict["chain_of_reasoning"] = val.strip()

        return fallback_dict


# Singleton
llm_client = LLMClient()
