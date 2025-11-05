# backend/services/gsb.py
import os
import time
from pathlib import Path
from typing import Dict, Any
import httpx

# Carrega variáveis de ambiente do arquivo .env se existir
try:
    from dotenv import load_dotenv
    # Procura .env no diretório backend/ (parent do services/)
    env_path = Path(__file__).parent.parent / '.env.local'
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass  # python-dotenv não instalado, usa apenas variáveis de ambiente do sistema

GSB_API_KEY = os.getenv("GSB_API_KEY", "")

def _payload(url: str) -> Dict[str, Any]:
    return {
        "client": {"clientId": "clicksafe", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

async def check_gsb(url: str) -> Dict[str, Any]:
    """
    Consulta o Google Safe Browsing v4 para uma única URL.
    Retorna um dict padronizado:
      { status: POSITIVE|NEGATIVE|UNKNOWN, reason: str, raw: {...}, elapsed_ms: int? }
    """
    if not GSB_API_KEY:
        return {"status": "UNKNOWN", "reason": "no_key", "raw": {}}

    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    params = {"key": GSB_API_KEY}
    body = _payload(url)

    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.post(endpoint, params=params, json=body)
        elapsed = int((time.perf_counter() - t0) * 1000)

        if r.status_code == 200:
            data = r.json()
            has_match = bool(data.get("matches"))
            return {
                "status": "POSITIVE" if has_match else "NEGATIVE",
                "reason": "ok",
                "raw": data if has_match else {},  # resposta vem vazia quando limpo
                "elapsed_ms": elapsed,
            }
        return {
            "status": "UNKNOWN",
            "reason": f"http_{r.status_code}",
            "raw": {"text": r.text[:500]},
        }
    except httpx.ReadTimeout:
        return {"status": "UNKNOWN", "reason": "timeout", "raw": {}}
    except Exception as e:
        return {"status": "UNKNOWN", "reason": f"error:{type(e).__name__}", "raw": {}}
