"""
Aplicação ClickSafe - Análise de URLs com integração ao banco de dados.
"""
import asyncio
import json
from urllib.parse import urlparse
from storage.db import (
    init_db,
    insert_analysis,
    insert_reputation_check,
    get_analysis_by_url,
    get_full_analysis,
    get_analyses_stats
)
from services.reputation import consolidate_reputation


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
    
    # Calcula score final (0-100)
    # _score vem de 0.0-1.0, converter para 0-100
    score = rep_result["_score"] * 100
    
    # Gera explicação básica (pode ser melhorada com IA depois)
    gsb_status = rep_result["sources"]["GOOGLE_SAFE_BROWSING"]["status"]
    explanation = f"Análise de reputação: Google Safe Browsing retornou {gsb_status}."
    if rep_result["sources"]["VIRUSTOTAL"]["status"] == "UNKNOWN":
        explanation += " VirusTotal e PhishTank ainda não configurados (mockados)."
    
    # Salva a análise no banco
    print("Salvando no banco de dados...")
    analysis_id = insert_analysis(
        url=url,
        normalized_url=normalized_url,
        score=score,
        explanation=explanation
    )
    print(f"Análise criada com ID: {analysis_id}")
    
    # Salva cada verificação de reputação
    print("Salvando verificações de reputação...")
    for source_name, source_data in rep_result["sources"].items():
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
    
    # Retorna análise completa
    return get_full_analysis(analysis_id)


async def main():
    """Função principal para testar a análise."""
    # Inicializa o banco de dados
    print("📦 Inicializando banco de dados...")
    init_db()
    
    # URLs de exemplo para testar
    test_urls = [
        "https://example.com",
        "https://google.com",
    ]
    
    for url in test_urls:
        print("\n" + "="*60)
        result = await analyze_url(url)
        
        if result:
            print(f"\nResultado da análise:")
            print(f"   ID: {result['id']}")
            print(f"   URL: {result['url']}")
            print(f"   Score: {result['score']:.2f}/100")
            print(f"   Verificações: {len(result['reputation_checks'])}")
            
            print("\n🔍 Detalhes das verificações:")
            for check in result['reputation_checks']:
                elapsed = check.get('elapsed_ms')
                elapsed_str = f"{elapsed}ms" if elapsed else "N/A"
                print(f"   - {check['source']}: {check['status']} "
                      f"({check.get('reason', 'N/A')}) "
                      f"[{elapsed_str}]")
        
        print("\n" + "="*60)
    
    # Mostra estatísticas
    print("\nEstatísticas do banco de dados:")
    stats = get_analyses_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")


if __name__ == "__main__":
    asyncio.run(main())
