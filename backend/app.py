"""
Aplicação ClickSafe - Análise de URLs com integração ao banco de dados.
"""
import asyncio
import json
import sys
from typing import Optional
from urllib.parse import urlparse
from storage.db import (
    init_db,
    clear_all_data,
    insert_analysis,
    insert_reputation_check,
    insert_heuristic_hit,
    insert_ai_request,
    get_analysis_by_url,
    get_full_analysis,
    get_analyses_stats
)
from services.reputation import consolidate_reputation
from services.xai import explain_result


def normalize_url(url: str) -> str:
    """
    Normaliza uma URL para comparação e armazenamento.
    Remove trailing slash, converte host para lowercase, etc.
    """
    parsed = urlparse(url)
    # Normaliza o host para lowercase
    normalized_host = parsed.netloc.lower()
    # Remove trailing slash do path (exceto se for apenas /)
    normalized_path = parsed.path.rstrip('/')
    # Reconstrói a URL normalizada
    normalized = f"{parsed.scheme}://{normalized_host}{normalized_path}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    if parsed.fragment:
        normalized += f"#{parsed.fragment}"
    return normalized


def _reputation_status_to_db_status(status: str) -> str:
    """
    Converte o status da API de reputação para o formato do banco.
    POSITIVE/NEGATIVE/UNKNOWN -> POSITIVE/NEGATIVE
    """
    if status == "POSITIVE":
        return "POSITIVE"
    elif status == "NEGATIVE":
        return "NEGATIVE"
    else:  # UNKNOWN
        return "NEGATIVE"  # UNKNOWN é tratado como NEGATIVE no banco


def calculate_final_score(
    reputation_score: float,
    heuristics_score: Optional[float] = None,
    reputation_weight: float = 0.7,
    heuristics_weight: float = 0.3
) -> float:
    """
    Calcula o score final combinando reputação e heurísticas.
    
    Args:
        reputation_score: Score de reputação (0-100)
        heuristics_score: Score de heurísticas (0-100, opcional)
        reputation_weight: Peso da reputação (padrão: 0.7)
        heuristics_weight: Peso das heurísticas (padrão: 0.3)
        
    Returns:
        Score final (0-100)
    """
    if heuristics_score is None:
        # Se heurísticas não estão implementadas, retorna apenas o score de reputação
        return reputation_score
    
    # Garante que os pesos somam 1.0
    total_weight = reputation_weight + heuristics_weight
    if total_weight != 1.0:
        reputation_weight = reputation_weight / total_weight
        heuristics_weight = heuristics_weight / total_weight
    
    # Calcula score ponderado
    final_score = (reputation_score * reputation_weight) + (heuristics_score * heuristics_weight)
    
    # Garante que está no range 0-100
    return max(0.0, min(100.0, final_score))


async def run_heuristics(url: str) -> dict:
    """
    Executa todas as heurísticas na URL.
    
    Retorna:
        {
            "score": float,  # Score de 0-100
            "hits": [        # Lista de heurísticas acionadas
                {
                    "code": str,
                    "severity": str,
                    "triggered": bool,
                    "details": str
                },
                ...
            ]
        }
    
    Por enquanto retorna stub (preparado para implementação futura).
    """
    # TODO: Implementar heurísticas quando o módulo estiver pronto
    # from services.heuristics import analyze_heuristics
    # return await analyze_heuristics(url)
    
    # Stub: retorna score neutro e lista vazia
    return {
        "score": 50.0,  # Score neutro quando não há heurísticas
        "hits": []
    }


async def analyze_url(url: str) -> dict:
    """
    Analisa uma URL completa:
    1. Consulta fontes de reputação (GSB real, VT/PT mockados)
    2. Salva no banco de dados
    3. Retorna o resultado completo
    """
    # Normaliza a URL
    normalized_url = normalize_url(url)
    
    # Verifica se já existe análise recente
    existing = get_analysis_by_url(normalized_url)
    if existing:
        print(f"Análise existente encontrada (ID: {existing['id']})")
        return get_full_analysis(existing['id'])
    
    # Consulta fontes de reputação
    print(f"Analisando URL: {url}")
    print(f"Normalizada: {normalized_url}")
    
    rep_result = await consolidate_reputation(url)
    
    # Executa heurísticas
    heuristics_result = await run_heuristics(url)
    
    # Calcula scores
    # _score vem de 0.0-1.0, converter para 0-100
    reputation_score = rep_result["_score"] * 100
    final_reputation_status = rep_result.get("final_status", "UNKNOWN")
    heuristics_score = heuristics_result["score"] if heuristics_result["hits"] else None
    
    # Calcula score final combinado
    final_score = calculate_final_score(
        reputation_score=reputation_score,
        heuristics_score=heuristics_score
    )
    
    # Gera explicação usando IA (xai)
    print("Gerando explicação com IA...")
    try:
        explanation = explain_result(url, heuristics_result, rep_result)
        print("✓ Explicação gerada com sucesso")
    except Exception as e:
        print(f"⚠ Erro ao gerar explicação com IA: {e}")
        # Fallback para explicação manual se a IA falhar
        explanation_parts = []
    
        gsb = rep_result["sources"]["GOOGLE_SAFE_BROWSING"]
        vt = rep_result["sources"].get("VIRUSTOTAL", {})
        
        if final_reputation_status == "POSITIVE":
            # Identifica qual fonte detectou a ameaça
            if gsb["status"] == "POSITIVE":
                explanation_parts.append("URL marcada como maliciosa por Google Safe Browsing.")
            elif vt.get("status") == "POSITIVE":
                explanation_parts.append("URL marcada como maliciosa por VirusTotal (GSB não detectou ameaça).")
        elif final_reputation_status == "NEGATIVE":
            # Todas as fontes verificadas retornaram negativo
            checked_sources = []
            if gsb["status"] == "NEGATIVE":
                checked_sources.append("Google Safe Browsing")
            if vt.get("status") == "NEGATIVE":
                checked_sources.append("VirusTotal")
            
            if checked_sources:
                sources_str = ", ".join(checked_sources)
                explanation_parts.append(f"URL verificada como segura por {sources_str}.")
            else:
                explanation_parts.append("URL verificada como segura.")
        else:  # UNKNOWN
            explanation_parts.append("Resultado indeterminado - algumas fontes não estão disponíveis.")
            if gsb["status"] != "UNKNOWN":
                explanation_parts.append(f"Google Safe Browsing: {gsb['status']}.")
            if vt.get("reason") == "stub":
                explanation_parts.append("VirusTotal ainda não configurado.")
        
        if heuristics_result["hits"]:
            triggered_count = sum(1 for h in heuristics_result["hits"] if h.get("triggered", False))
            explanation_parts.append(f"{triggered_count} heurística(s) acionada(s).")
        else:
            explanation_parts.append("Heurísticas ainda não implementadas.")
        
        explanation = " ".join(explanation_parts) if explanation_parts else "Análise concluída."
    
    # Salva a análise no banco
    print("Salvando no banco de dados...")
    analysis_id = insert_analysis(
        url=url,
        normalized_url=normalized_url,
        score=final_score,
        explanation=explanation
    )
    print(f"Análise criada com ID: {analysis_id}")
    
    # Salva cada verificação de reputação
    print("Salvando verificações de reputação...")
    for source_name, source_data in rep_result["sources"].items():
        # APIVOID desabilitado temporariamente - ignora se aparecer
        if source_name == "APIVOID":
            print(f"   - {source_name}: ignorado (desabilitado temporariamente)")
            continue
        
        # Só salva se foi realmente verificada (não foi "not_checked")
        if source_data.get("reason") == "not_checked":
            print(f"   - {source_name}: não verificado (verificação anterior detectou ameaça)")
            continue
        
        status = _reputation_status_to_db_status(source_data["status"])
        raw_json = json.dumps(source_data)
        reason = source_data.get("reason", "ok")
        elapsed_ms = source_data.get("elapsed_ms")
        
        insert_reputation_check(
            analysis_id=analysis_id,
            source=source_name,
            status=status,
            raw_json=raw_json,
            reason=reason,
            elapsed_ms=elapsed_ms
        )
        print(f"   ✓ {source_name}: {status} ({reason})")
    
    # Salva resultados de heurísticas (vazias por hora)
    if heuristics_result["hits"]:
        print("Salvando resultados de heurísticas...")
        for hit in heuristics_result["hits"]:
            insert_heuristic_hit(
                analysis_id=analysis_id,
                heuristic_code=hit["code"],
                severity=hit["severity"],
                triggered=hit.get("triggered", False),
                details=hit.get("details")
            )
            print(f"   ✓ {hit['code']}: {hit['severity']} (triggered={hit.get('triggered', False)})")
    else:
        print("Heurísticas vazias (não implementadas ainda)")
    
    # Salva requisição de IA
    print("Salvando requisição de IA...")
    try:
        from services.xai import MODEL, build_prompt
        prompt = build_prompt(url, heuristics_result, rep_result)
        insert_ai_request(
            analysis_id=analysis_id,
            model=MODEL,
            prompt=prompt,
            response=explanation,
            risk_score=final_score,
            meta=json.dumps({
                "reputation_score": reputation_score,
                "heuristics_score": heuristics_score,
                "final_status": final_reputation_status
            })
        )
        print(f"   ✓ Requisição de IA salva (modelo: {MODEL})")
    except Exception as e:
        print(f"   ⚠ Erro ao salvar requisição de IA: {e}")
    
    # Retorna análise completa
    return get_full_analysis(analysis_id)


async def main():
    """Função principal para testar a análise."""
    # URLs de teste - pode editar aqui para adicionar suas URLs
    TEST_URLS = [
        "https://google.com",
        "https://example.com",
        # Adicione mais URLs aqui para testar
        # "http://malware.testing.google.test/testing/malware/",
    ]
    
    # Verifica se deve limpar o banco antes
    clear_db = "--clear" in sys.argv or "-c" in sys.argv
    
    # Pega URLs dos argumentos da linha de comando
    urls_from_args = [arg for arg in sys.argv[1:] if not arg.startswith("--") and not arg.startswith("-")]
    
    # Decide quais URLs usar
    if urls_from_args:
        test_urls = urls_from_args
    else:
        test_urls = TEST_URLS
    
    # Inicializa o banco de dados
    print("Inicializando banco de dados...")
    init_db()
    
    # Limpa o banco se solicitado
    if clear_db:
        print("\nLimpando banco de dados...")
        clear_all_data()
        print()
    
    # Processa cada URL
    for url in test_urls:
        print("\n" + "="*60)
        result = await analyze_url(url)
        
        if result:
            # Determina status final baseado no score
            score = result['score']
            if score >= 80:
                risk_status = "MALICIOSO"
                risk_indicator = "POSITIVE"
            elif score >= 50:
                risk_status = "SUSPEITO"
                risk_indicator = "UNKNOWN"
            else:
                risk_status = "SEGURO"
                risk_indicator = "NEGATIVE"
            print(f"\n Resultado da análise:")
            print(f"   ID: {result['id']}")
            print(f"   URL: {result['url']}")
            print(f"   {risk_indicator} Status: {risk_status}")
            print(f"   Score de Risco: {score:.2f}/100 (0=Seguro, 100=Malicioso)")
            print(f"   Verificações: {len(result['reputation_checks'])}")
            
            # Mostra explicação gerada pela IA
            if result.get('explanation'):
                print(f"\nExplicação (IA):")
                print(f"   {result['explanation']}")
            
            print("\n🔍 Detalhes das verificações:")
            for check in result['reputation_checks']:
                elapsed = check.get('elapsed_ms')
                elapsed_str = f"{elapsed}ms" if elapsed else "N/A"
                check_status = check['status']
                if check_status == "POSITIVE":
                    status_indicator = "POSITIVE"
                elif check_status == "NEGATIVE":
                    status_indicator = "NEGATIVE"
                else:
                    status_indicator = "UNKNOWN"
                
                print(f"   {status_indicator} - {check['source']} "
                      f"({check.get('reason', 'N/A')}) "
                      f"[{elapsed_str}]")
        
        print("\n" + "="*60)
    
    # Mostra estatísticas
    print("\n Estatísticas do banco de dados:")
    stats = get_analyses_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ["--help", "-h"]:
        print("Uso: python app.py [--clear] [URL1] [URL2] ...")
        print("\nOpções:")
        print("  --clear, -c    Limpa o banco de dados antes de executar")
        print("  URL1 URL2 ...  URLs para analisar (opcional)")
        print("\nExemplos:")
        print("  python app.py")
        print("  python app.py --clear")
        print("  python app.py https://example.com")
        print("  python app.py --clear https://google.com https://example.com")
        sys.exit(0)
    
    asyncio.run(main())
