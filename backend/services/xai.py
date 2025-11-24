#backend/services/xai.py

import json
import subprocess
from typing import Dict, Any

MODEL = "mistral"

def _build_prompt(url: str, heuristics: Dict[str, Any], reputation: Dict[str, Any], final_score: float = None) -> str:

    heur_score = heuristics.get("score", 0.0)
    hits = heuristics.get("hits", [])
    rep_score = reputation.get("_score", 0.0)
    final_status = reputation.get("final_status", "UNKNOWN")
    sources = reputation.get("sources", {})

    # Determina classificação baseada no score final
    if final_score is not None:
        if final_score >= 80:
            risk_classification = "MALICIOSO"
        elif final_score >= 50:
            risk_classification = "SUSPEITO"
        else:
            risk_classification = "SEGURO"
        final_score_str = f"{final_score:.2f}"
    else:
        risk_classification = "INDETERMINADO"
        final_score_str = "N/A"

    # Conta heurísticas acionadas por severidade
    triggered_by_severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    triggered_hits = []
    for hit in hits:
        if hit.get("triggered", False):
            severity = hit.get("severity", "MEDIUM")
            triggered_by_severity[severity] = triggered_by_severity.get(severity, 0) + 1
            triggered_hits.append({
                "code": hit.get("code"),
                "severity": severity,
                "details": hit.get("details", "")
            })

    # Resumo das fontes de reputação
    gsb = sources.get("GOOGLE_SAFE_BROWSING", {})
    vt = sources.get("VIRUSTOTAL", {})
    gsb_status = gsb.get("status", "UNKNOWN")
    vt_status = vt.get("status", "UNKNOWN")

    return f"""
És um assistente de cibersegurança. Gera um resumo curto e objetivo para o utilizador final.

URL analisada: {url}

[Score Final de Risco]
- Score: {final_score_str}/100
- Classificação: {risk_classification}
- Interpretação: 0-49=SEGURO, 50-79=SUSPEITO, 80-100=MALICIOSO

[Reputação]
[Reputaçao]
- Score (0-100): {rep_score:.2f}/100
- Estado geral: {final_status}  
- Fontes:
  - Google Safe Browsing: {sources.get("GOOGLE_SAFE_BROWSING",{})}
  - VirusTotal: {sources.get("VIRUSTOTAL",{})}
  - APIVOID: (desabilitado temporariamente)

[Heurísticas]
- Score (0-100): {heur_score:.2f}/100
- Heurísticas acionadas: {len(triggered_hits)} de {len(hits)} total
- Por severidade: LOW={triggered_by_severity['LOW']}, MEDIUM={triggered_by_severity['MEDIUM']}, HIGH={triggered_by_severity['HIGH']}, CRITICAL={triggered_by_severity['CRITICAL']}
- Principais detecções: {', '.join([h['code'] for h in triggered_hits[:5]]) if triggered_hits else 'Nenhuma'}

Instruções de resposta organizada:
1) Comece com um rótulo de risco: "{risk_classification}" (baseado no score {final_score_str}/100)
2) Explique em 2-4 frases os motivos principais (cite fontes de reputação e heurísticas mais relevantes)
3) Termine com uma recomendação prática de forma a conferir clareza e indicações sobre o que fazer (ex.: "evitar clicar", "verificar remetente", etc.).
Evite conceitos muito técnicos de forma excessiva e não inventes dados não fornecidos.
    """.strip()


# Exportar build_prompt como função pública para uso em app.py
def build_prompt(url: str, heuristics: Dict[str, Any], reputation: Dict[str, Any], final_score: float = None) -> str:
    """Função pública para construir o prompt."""
    return _build_prompt(url, heuristics, reputation, final_score)


def explain_result(url: str, heuristics: Dict, reputation: Dict, final_score: float = None) -> str:
    
    prompt = _build_prompt(url, heuristics, reputation, final_score)

    proc = subprocess.run(
        ["ollama", "run", MODEL],
        input=prompt,
        text=True,
        capture_output=True,
        timeout=120
    )

    if proc.returncode != 0:
        raise RuntimeError(f"ollama erro: {proc.stderr.strip()}")

    return proc.stdout.strip()
