# backend/services/reputation.py
from typing import Dict
from .gsb import check_gsb
from .vt import check_vt


def _status_to_score(status: str) -> float:
    """
    Converte status de reputação para score numérico (0.0 = seguro, 1.0 = perigoso).
    
    - POSITIVE (malicioso): 1.0
    - NEGATIVE (seguro/não malicioso): 0.0
    - UNKNOWN (indeterminado): 0.5
    """
    return {"POSITIVE": 1.0, "NEGATIVE": 0.0, "UNKNOWN": 0.5}.get(status, 0.5)

async def consolidate_reputation(url: str) -> Dict:
    """
    Verifica reputação de forma sequencial:
    1. Verifica GSB primeiro
    2. Se GSB for POSITIVE (malicioso), retorna imediatamente
    3. Se GSB for NEGATIVE (seguro), verifica VirusTotal
    4. Se VirusTotal for POSITIVE, retorna como malicioso
    5. Se VirusTotal for NEGATIVE, verifica PhishTank
    6. Se PhishTank for POSITIVE, retorna como malicioso
    7. Se PhishTank for NEGATIVE, retorna como seguro
    """
    sources = {}
    
    # 1. Verifica Google Safe Browsing primeiro
    print("  Verificando Google Safe Browsing...")
    gsb = await check_gsb(url)
    sources["GOOGLE_SAFE_BROWSING"] = gsb
    
    # Se GSB for POSITIVE (malicioso), retorna imediatamente
    if gsb["status"] == "POSITIVE":
        print("  GSB detectou ameaça - marcando como malicioso")
        # Preenche os outros como não verificados
        sources["VIRUSTOTAL"] = {"status": "UNKNOWN", "reason": "not_checked", "raw": {}}
        sources["PHISHTANK"] = {"status": "UNKNOWN", "reason": "not_checked", "raw": {}}
        return {"sources": sources, "_score": 1.0, "final_status": "POSITIVE"}
    
    # 2. GSB foi NEGATIVE, verifica VirusTotal
    print("  GSB não detectou ameaça - verificando VirusTotal...")
    
    vt = await check_vt(url)
    sources["VIRUSTOTAL"] = vt
    
    # Se VirusTotal estiver implementado e for POSITIVE, retorna
    if vt["status"] == "POSITIVE":
        print("  VirusTotal detectou ameaça - marcando como malicioso")
        sources["PHISHTANK"] = {"status": "UNKNOWN", "reason": "not_checked", "raw": {}}
        return {"sources": sources, "_score": 1.0, "final_status": "POSITIVE"}
    
    # 3. VirusTotal foi NEGATIVE ou UNKNOWN, verifica PhishTank
    if vt["status"] == "NEGATIVE":
        print("  VirusTotal não detectou ameaça - verificando PhishTank...")
    else:
        print("  VirusTotal não disponível - verificando PhishTank...")
    
    # TODO: Implementar check_pt quando estiver disponível
    # pt = await check_pt(url)
    pt = {"status": "UNKNOWN", "reason": "stub", "raw": {}}  # Stub por enquanto
    sources["PHISHTANK"] = pt
    
    # Se PhishTank estiver implementado e for POSITIVE, retorna
    if pt["status"] == "POSITIVE":
        print("  PhishTank detectou ameaça - marcando como malicioso")
        return {"sources": sources, "_score": 1.0, "final_status": "POSITIVE"}
    
    # 4. Todas as fontes verificadas retornaram NEGATIVE ou UNKNOWN
    # Se todas forem NEGATIVE, é seguro. Se alguma for UNKNOWN, é indeterminado.
    all_negative = all(s["status"] == "NEGATIVE" for s in sources.values())
    
    if all_negative:
        print("  Todas as fontes verificadas indicam que a URL é segura")
        final_status = "NEGATIVE"
        score = 0.0
    else:
        # Tem pelo menos uma UNKNOWN
        print("  Algumas fontes não estão disponíveis - resultado indeterminado")
        final_status = "UNKNOWN"
        score = 0.5
    
    return {"sources": sources, "_score": score, "final_status": final_status}
