#backend/services/apivoidrep.py
import os
import time
import requests
import asyncio
from typing import Dict
from pathlib import Path

try:
    from dotenv import load_dotenv
    env_path = Path(__file__).resolve().parents[1] / ".env.local"
    if env_path.exists():
        load_dotenv(env_path)
except Exception:
    pass

async def check_apivoid(url: str, timeout: int = 5) -> Dict:
    start_time = time.time()
    api_key = os.getenv("APIVOID_API_KEY")

    #Não há API Key: não falha, apenas marca como UNKNOWN
    if not api_key:
        return {
            "status": "UNKNOWN",
            "reason": "no_key",
            "raw": {},
            "elapsed_ms": int((time.time() - start_time) * 1000)
        }

    try:
        #Endpoint APIVoid (modelo Pay-As-You-Go)
        endpoint = "https://api.apivoid.com/urlrep/v1/pay-as-you-go/"
        params = {"key": api_key, "url": url}

        #Executar requests sem bloquear o event loop
        response = await asyncio.to_thread(
            requests.get, endpoint, params=params, timeout=timeout
        )

        print("\nDEBUG APIVOID RAW RESPONSE:\n", response.text, "\n")

        #Pode dar erro se a resposta for HTML em vez de JSON
        try:
            data = response.json()
        except Exception:
            return {
                "status": "UNKNOWN",
                "reason": "invalid_json",
                "raw": {"response_text": response.text},
                "elapsed_ms": int((time.time() - start_time) * 1000)
            }

        elapsed = int((time.time() - start_time) * 1000)

        #"score" 0 = seguro, >0 = suspeito/malicioso
        score = data.get("data", {}).get("report", {}).get("score", 0)
        status = "NEGATIVE" if score == 0 else "POSITIVE"

        return {
            "status": status,
            "reason": "ok",
            "raw": data,
            "elapsed_ms": elapsed
        }

    except Exception as e:
        return {
            "status": "UNKNOWN",
            "reason": f"error:{type(e).__name__}:{str(e)}",
            "raw": {},
            "elapsed_ms": int((time.time() - start_time) * 1000)
        }
