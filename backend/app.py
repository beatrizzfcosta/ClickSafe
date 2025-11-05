"""
Exemplo de uso do banco de dados ClickSafe - validar o schema e o db.py.
"""
from storage.db import (
    init_db,
    insert_analysis,
    insert_reputation_check,
    insert_heuristic_hit,
    get_analysis_by_url,
    get_full_analysis,
    get_analyses_stats
)
import json


def example_usage():
    """Exemplo de como usar o banco de dados."""
    
    # 1. Inicializar o banco de dados (executar apenas uma vez)
    print(" Inicializando banco de dados...")
    init_db()
    
    # 2. Normalizar URL (exemplo simples)
    url = "https://example.com/path/"
    normalized_url = url.lower().rstrip('/')
    
    # 3. Verificar se já existe análise
    existing_analysis = get_analysis_by_url(normalized_url)
    if existing_analysis:
        print(f" Análise existente encontrada (ID: {existing_analysis['id']})")
        print(f" Score: {existing_analysis['score']}")
    
    # 4. Simular uma nova análise
    print("\nCriando nova análise...")
    analysis_id = insert_analysis(
        url=url,
        normalized_url=normalized_url,
        score=75.5,
        explanation="Esta URL apresenta alguns indicadores de risco moderados."
    )
    print(f"Análise criada com ID: {analysis_id}")
    
    # 5. Adicionar verificações de reputação
    print("\nAdicionando verificações de reputação...")
    
    insert_reputation_check(
        analysis_id=analysis_id,
        source='GOOGLE_SAFE_BROWSING',
        status='NEGATIVE',
        raw_json=json.dumps({"status": "ok", "threats": []}),
        reason='ok',
        elapsed_ms=150
    )
    
    insert_reputation_check(
        analysis_id=analysis_id,
        source='VIRUSTOTAL',
        status='NEGATIVE',
        raw_json=json.dumps({"detections": 0, "total": 87}),
        reason='ok',
        elapsed_ms=320
    )
    
    print("Verificações de reputação adicionadas")
    
    # 6. Adicionar resultados de heurísticas
    print("\nAdicionando resultados de heurísticas...")
    
    insert_heuristic_hit(
        analysis_id=analysis_id,
        type='DOMAIN_AGE',
        severity='MEDIUM',
        status='TRUE',
        details='Domínio criado há 6 meses (risco moderado)'
    )
    
    insert_heuristic_hit(
        analysis_id=analysis_id,
        type='PATH_LENGTH_EXCESSIVE',
        severity='LOW',
        status='TRUE',
        details='Path com 45 caracteres'
    )
    
    insert_heuristic_hit(
        analysis_id=analysis_id,
        type='DOMAIN_HAS_HTTPS',
        severity='LOW',
        status='FALSE',
        details='HTTPS válido presente'
    )
    
    print("Heurísticas adicionadas")
    
    # 7. Buscar análise completa
    print("\nBuscando análise completa...")
    full_analysis = get_full_analysis(analysis_id)
    if full_analysis:
        print(f"   URL: {full_analysis['url']}")
        print(f"   Score: {full_analysis['score']}")
        print(f"   Verificações de reputação: {len(full_analysis['reputation_checks'])}")
        print(f"   Heurísticas acionadas: {sum(1 for h in full_analysis['heuristics_hits'] if h['status'] == 'TRUE')}")
    
    # 8. Ver estatísticas
    print("\nEstatísticas do banco de dados:")
    stats = get_analyses_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\nExemplo concluído!")


if __name__ == "__main__":
    example_usage()

