import os
import time
from pathlib import Path
from typing import Dict, Any
import httpx
from urllib.parse import urlparse, urlunparse

# carrega .env (igual ao teu)
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent.parent / '.env.local'
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass

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

async def expand_url(url: str, timeout: float = 10.0) -> str:
    """
    Expande redirecionamentos (bit.ly, etc) e devolve a URL final.
    Se falhar, devolve a URL original.
    """
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
            # HEAD costuma ser suficiente e menos pesado; alguns encurtadores rejeitam HEAD -> fallback para GET
            r = await client.head(url, allow_redirects=True)
            final = r.url if r.status_code < 400 else r.url
            # se HEAD falhar, tenta GET
            if r.status_code >= 400:
                r2 = await client.get(url, allow_redirects=True)
                final = r2.url
            return str(final)
    except Exception:
        return url

def canonicalize_url(u: str) -> str:
    """
    Canonicalização simples:
     - lowercase scheme e host,
     - remove fragment,
     - remove default ports,
     - garante path (/) se vazio.
    NOTA: o Safe Browsing tem regras próprias mais complexas (hashing, etc).
    """
    p = urlparse(u)
    scheme = (p.scheme or "http").lower()
    netloc = p.hostname.lower() if p.hostname else ""
    if p.port and not (p.scheme == "http" and p.port == 80 or p.scheme == "https" and p.port == 443):
        netloc += f":{p.port}"
    path = p.path or "/"
    # remove fragment
    normalized = urlunparse((scheme, netloc, path, "", p.query, ""))
    return normalized

async def check_gsb(url: str, use_test_url: bool = False) -> Dict[str, Any]:
    """
    Faz:
     1) expande encurtadores e segue redirects
     2) canonicaliza a URL
     3) chama threatMatches:find
    """
    if not GSB_API_KEY:
        return {"status": "UNKNOWN", "reason": "no_key", "raw": {}}

    # Opcional: URL de teste conhecida para validar request (deve sempre dar match)
    if use_test_url:
        # Exemplo de teste: MALWARE. (verifica docs/testsafebrowsing)
        url_to_check = "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL"
    else:
        # expandir e canonicalizar
        expanded = await expand_url(url, timeout=8.0)
        url_to_check = canonicalize_url(expanded)

    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    params = {"key": GSB_API_KEY}
    body = _payload(url_to_check)

    t0 = time.perf_counter()
    try:
        # timeout maior para dar tempo a resolver DNS e redirecionamentos
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(endpoint, params=params, json=body)
        elapsed = int((time.perf_counter() - t0) * 1000)

        if r.status_code == 200:
            data = r.json()
            has_match = bool(data.get("matches"))
            return {
                "status": "POSITIVE" if has_match else "NEGATIVE",
                "reason": "ok",
                "raw": data if has_match else {},
                "elapsed_ms": elapsed,
                "checked_url": url_to_check,
                "expanded_from": url if url != url_to_check else None,
            }
        # retorna motivo HTTP para debugging
        return {
            "status": "UNKNOWN",
            "reason": f"http_{r.status_code}",
            "raw": {"text": r.text[:1000]},
        }
    except httpx.ReadTimeout:
        return {"status": "UNKNOWN", "reason": "timeout", "raw": {}}
    except Exception as e:
        return {"status": "UNKNOWN", "reason": f"error:{type(e).__name__}", "raw": {}}
