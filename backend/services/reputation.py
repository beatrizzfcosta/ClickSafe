# backend/services/reputation.py
from typing import Dict
from .gsb import check_gsb

def _status_to_score(status: str) -> float:
    """
    Converte status de reputação para score numérico (0.0 = seguro, 1.0 = perigoso).
    
    - POSITIVE (malicioso): 1.0
    - NEGATIVE (seguro/não malicioso): 0.0
    - UNKNOWN (indeterminado): 0.5
    """
    return {"POSITIVE": 1.0, "NEGATIVE": 0.0, "UNKNOWN": 0.5}.get(status, 0.5)

async def consolidate_reputation(url: str) -> Dict:
    gsb = await check_gsb(url)
    # por enquanto, VT e PT ficam como UNKNOWN (stubs)
    vt  = {"status":"UNKNOWN","reason":"stub","raw":{}}
    pt  = {"status":"UNKNOWN","reason":"stub","raw":{}}

    sources = {
        "GOOGLE_SAFE_BROWSING": gsb,
        "VIRUSTOTAL":           vt,
        "PHISHTANK":            pt,
    }
    score = sum(_status_to_score(s["status"]) for s in sources.values()) / len(sources)
    return {"sources": sources, "_score": round(score, 4)}
