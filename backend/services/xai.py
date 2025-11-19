#backend/services/xai.py

import json
import subprocess
from typing import Dict, Any

MODEL = "mistral"

def _build_prompt(url: str, heuristics: Dict[str, Any], reputation: Dict[str, Any]) -> str:

    heur_score = heuristics.get("score")
    hits = heuristics.get("hits", [])
    rep_score = reputation.get("_score")
    final_status = reputation.get("final_status", "UNKNOWN")
    sources = reputation.get("sources", {})

    return f"""
És um assistente de cibersegurança. Gera um resumo curto e objetivo para o utilizador final.

URL analisada: {url}

[Reputação]
- Score (0-1): {rep_score}
- Estado final: {final_status}
- Fontes:
  - Google Safe Browsing: {sources.get("GOOGLE_SAFE_BROWSING",{})}
  - VirusTotal: {sources.get("VIRUSTOTAL",{})}
  - APIVOID: (desabilitado temporariamente)

[Heurísticas]
- Score (0-100): {heur_score}
- Ocorrências: {json.dumps(hits, ensure_ascii=False)}

Instruções de resposta organizada:
1) Comece com um rótulo de risco: "SEGURO", "SUSPEITO" ou "MALICIOSO".
2) Explique em 2–4 frases os motivos principais (cite as fontes que acusaram algo, se for o caso).
3) Termine com uma recomendação prática de forma a conferir clareza e indicações sobre o que fazer (ex.: “evitar clicar”, “verificar remetente”, etc.).
Evite conceitos muito técnicos de froma excessiva e não inventes dados não fornecidos.
    """.strip()

def explain_result(url: str, heuristics: Dict, reputation: Dict) -> str:
    
    prompt = _build_prompt(url, heuristics, reputation)

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
