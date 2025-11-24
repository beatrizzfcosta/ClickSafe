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
from services.heuristics import (
    extract_url_components,
    # Domain heuristics
    check_domain_age_recent,
    check_domain_age_expiring,
    check_suspicious_tld,
    check_ip_instead_of_domain,
    check_similar_known_domains,
    check_subdomains_sublevels,
    check_domain_hyphens,
    usa_https,
    certificado_ssl_ok,
    check_dns_records,
    check_suspicious_server_location,
    # Path heuristics
    check_long_path,
    check_admin_paths,
    check_suspicious_filenames,
    check_executable_extensions,
    check_social_engineering_path,
    # Parameters heuristics
    check_excessive_parameters,
    check_sensitive_parameters,
    check_long_encoded_parameters,
    check_redirect_parameters,
    check_personal_data_parameters,
    # General heuristics
    check_url_shortener,
    check_multiple_redirects,
    check_embedded_protocols,
    check_mixed_languages,
    check_symbols_emojis,
    check_appealing_phrases,
    check_repeated_words,
)


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


def _get_heuristics_config() -> dict:
    """
    Busca todas as configurações de heurísticas do banco de dados.
    Retorna um dicionário: {code: {"severity": str}}
    """
    from storage.db import get_db
    config = {}
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT code, default_severity FROM heuristics"
        )
        for row in cursor.fetchall():
            config[row[0]] = {
                "severity": row[1]
            }
    return config


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
    """
    # Extrai componentes da URL
    dominio, caminho, parametros = extract_url_components(url)
    
    # Mapeamento de funções para códigos de heurísticas
    # Formato: (função, código_heurística, argumentos, descrição)
    heuristics_map = [
        # Domain Heuristics
        (check_domain_age_recent, "DOMAIN_AGE", (dominio,), "Domínio muito recente"),
        (check_domain_age_expiring, "DOMAIN_EXPIRATION", (dominio,), "Domínio prestes a expirar"),
        (check_suspicious_tld, "DOMAIN_TLD_RISK", (dominio,), "TLD suspeito"),
        (check_ip_instead_of_domain, "DOMAIN_IS_IP_ADDRESS", (dominio,), "Domínio é endereço IP"),
        (check_similar_known_domains, "DOMAIN_SIMILAR_TO_BRAND", (dominio,), "Similaridade com marca conhecida"),
        (check_subdomains_sublevels, "DOMAIN_MULTIPLE_SUBLEVELS", (dominio,), "Múltiplos subníveis"),
        (check_domain_hyphens, "DOMAIN_HYPHENS_USAGE", (dominio,), "Uso de hífens no domínio"),
        # DOMAIN_HAS_HTTPS: acionada quando NÃO tem HTTPS (inversão)
        (lambda u: not usa_https(u), "DOMAIN_HAS_HTTPS", (url,), "Ausência de HTTPS"),
        # DOMAIN_SSL_INVALID: acionada quando SSL é inválido (inversão)
        (lambda u: certificado_ssl_ok(u) is False, "DOMAIN_SSL_INVALID", (url,), "Certificado SSL inválido"),
        # DOMAIN_DNS_ANOMALY: acionada quando há anomalia (False ou None)
        (lambda d: check_dns_records(d) is not True, "DOMAIN_DNS_ANOMALY", (dominio,), "Anomalia DNS"),
        (check_suspicious_server_location, "DOMAIN_GEOLOCATION_RISK", (dominio,), "Risco de geolocalização"),
        
        # Path Heuristics
        (check_long_path, "PATH_LENGTH_EXCESSIVE", (caminho,), "Caminho muito longo"),
        (check_admin_paths, "PATH_ADMIN_DIRECTORIES", (caminho,), "Diretórios administrativos"),
        (check_suspicious_filenames, "PATH_SUSPICIOUS_TERMS", (caminho,), "Termos suspeitos no caminho"),
        (check_executable_extensions, "PATH_EXECUTABLE_DISGUISED", (caminho,), "Executável disfarçado"),
        (check_social_engineering_path, "PATH_SOCIAL_ENGINEERING_TERMS", (caminho,), "Termos de engenharia social"),
        
        # Parameters Heuristics
        (check_excessive_parameters, "PARAMS_EXCESSIVE_NUMBER", (parametros,), "Número excessivo de parâmetros"),
        (check_sensitive_parameters, "PARAMS_SENSITIVE_VARIABLES", (parametros,), "Variáveis sensíveis"),
        (check_long_encoded_parameters, "PARAMS_LONG_OR_ENCODED_VALUES", (parametros,), "Valores longos ou codificados"),
        (check_redirect_parameters, "PARAMS_REDIRECT_KEYWORD", (parametros,), "Palavra-chave de redirecionamento"),
        (check_personal_data_parameters, "PARAMS_PERSONAL_DATA_INCLUDED", (parametros,), "Dados pessoais incluídos"),
        
        # General Heuristics
        (check_url_shortener, "SHORTENER_USAGE", (dominio,), "Uso de encurtador"),
        (check_multiple_redirects, "MULTIPLE_REDIRECTS", (url,), "Múltiplos redirecionamentos"),
        (check_embedded_protocols, "EMBEDDED_PROTOCOLS", (url,), "Protocolos embutidos"),
        (check_mixed_languages, "LANGUAGE_MIX", (url,), "Mistura de idiomas"),
        (check_symbols_emojis, "EMOJI_OR_SYMBOL_USAGE", (url,), "Uso de emoji ou símbolos"),
        (check_appealing_phrases, "ATTRACTIVE_PHRASES", (url,), "Frases atrativas"),
        (check_repeated_words, "KEYWORD_REPETITION", (url,), "Repetição de palavras-chave"),
    ]
    
    # Busca configurações de todas as heurísticas de uma vez
    heuristics_config = _get_heuristics_config()
    
    # Valores simplificados por severidade (quando acionadas)
    # Fórmula simples: soma direta, máximo 100
    SEVERITY_SCORES = {
        "LOW": 5.0,      # 5 pontos por heurística LOW
        "MEDIUM": 15.0,  # 15 pontos por heurística MEDIUM
        "HIGH": 40.0,    # 40 pontos por heurística HIGH
        "CRITICAL": 70.0 # 70 pontos por heurística CRITICAL
    }
    
    hits = []
    score_by_severity = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0
    }
    
    # Executa cada heurística
    for func, code, args, description in heuristics_map:
        try:
            # Chama a função
            result = func(*args)
            
            # Busca configuração da heurística (severidade)
            config = heuristics_config.get(code, {"severity": "MEDIUM"})
            severity = config["severity"]
            
            # Interpreta o resultado
            # True = acionada (risco), False = não acionada (seguro), None = erro/indeterminado
            if result is True:
                triggered = True
                details = f"{description}: detectado"
                # Conta quantas heurísticas dessa severidade foram acionadas
                score_by_severity[severity] += 1
            elif result is False:
                triggered = False
                details = f"{description}: não detectado"
            else:  # None ou erro
                # Em caso de erro, não considera como acionada mas registra
                triggered = False
                details = f"{description}: erro na verificação"
            
            # Adiciona ao resultado (sem weight)
            hits.append({
                "code": code,
                "severity": severity,
                "triggered": triggered,
                "details": details
            })
            
        except Exception as e:
            print(f"⚠ Erro ao executar heurística {code}: {e}")
            # Em caso de erro, adiciona como não acionada
            config = heuristics_config.get(code, {"severity": "MEDIUM"})
            hits.append({
                "code": code,
                "severity": config["severity"],
                "triggered": False,
                "details": f"Erro: {str(e)}"
            })
    
    # Calcula score final de forma simples: soma direta dos pontos
    final_score = 0.0
    score_breakdown = {}
    
    for severity, count in score_by_severity.items():
        if count > 0:
            points = count * SEVERITY_SCORES[severity]
            final_score += points
            score_breakdown[severity] = {
                "count": count,
                "points_per_item": SEVERITY_SCORES[severity],
                "total_points": points
            }
    
    # Limita o máximo a 100
    final_score = min(100.0, final_score)
    
    # Log do cálculo (simplificado)
    print(f"\n Cálculo do Score de Heurísticas:")
    if score_breakdown:
        for severity, breakdown in score_breakdown.items():
            print(f"   {severity}: {breakdown['count']} heurística(s) × {breakdown['points_per_item']} = {breakdown['total_points']} pontos")
        print(f"   Score total: {final_score:.2f}/100")
    else:
        print(f"   Nenhuma heurística acionada")
        print(f"   Score: 0.00/100")
    
    return {
        "score": final_score,
        "hits": hits
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
    # Score de heurísticas (sempre existe, será 0.0 se nenhuma acionada)
    heuristics_score = heuristics_result.get("score", 0.0)
    
    # Log dos scores individuais
    print(f"\nScores Individuais:")
    print(f"   Reputação: {reputation_score:.2f}/100")
    print(f"   Heurísticas: {heuristics_score:.2f}/100")
    
    # Calcula score final combinado
    final_score = calculate_final_score(
        reputation_score=reputation_score,
        heuristics_score=heuristics_score
    )
    
    # Log do cálculo final
    print(f"\n Cálculo do Score Final:")
    print(f"   (Reputação × 70%) + (Heurísticas × 30%)")
    print(f"   ({reputation_score:.2f} × 0.7) + ({heuristics_score:.2f} × 0.3)")
    print(f"   = {reputation_score * 0.7:.2f} + {heuristics_score * 0.3:.2f}")
    print(f"   = {final_score:.2f}/100")
    
    # Gera explicação usando IA (xai)
    print("Gerando explicação com IA...")
    try:
        explanation = explain_result(url, heuristics_result, rep_result, final_score)
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
        prompt = build_prompt(url, heuristics_result, rep_result, final_score)
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
            
            print("\n Detalhes das verificações:")
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
