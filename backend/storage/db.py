"""
Módulo de gerenciamento do banco de dados SQLite para ClickSafe.
"""
# cursor.lastrowid: retorna o ID gerado automaticamente pelo AUTOINCREMENT após um INSERT (ex: PRIMARY KEY AUTOINCREMENT)
import sqlite3
import os
from pathlib import Path
from typing import Optional, Dict, List, Any
from contextlib import contextmanager
from datetime import datetime
from urllib.parse import urlparse


# Caminho padrão do banco de dados
DB_PATH = os.getenv('CLICKSAFE_DB_PATH', 'clicksafe.db')
SCHEMA_PATH = Path(__file__).parent / 'schemas.sql'


def get_db_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    """
    Cria uma conexão com o banco de dados SQLite.
    db_path: Caminho para o arquivo do banco de dados
    return: Conexão SQLite configurada
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # Permite acessar colunas por nome
    return conn

@contextmanager
def get_db(db_path: str = DB_PATH):
    """
    Context manager para gerenciar conexões de banco de dados.
    Garante que a conexão seja fechada corretamente.
    Usage: with get_db() as conn: ...
    """
    conn = get_db_connection(db_path)
    try:
        # Importante em SQLite: garantir integridade referencial
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: str = DB_PATH, schema_path: Path = SCHEMA_PATH) -> None:
    """
    Inicializa o banco de dados criando todas as tabelas.
    db_path: Caminho para o arquivo do banco de dados
    schema_path: Caminho para o arquivo SQL com o schema
    """
    from pathlib import Path as P
    seed_path = P(__file__).parent / 'seed_heuristics.sql'
    
    with open(schema_path, 'r', encoding='utf-8') as f:
        schema_sql = f.read()
    
    with get_db(db_path) as conn:
        conn.executescript(schema_sql)
        
        # Popular tabela heuristics
        if seed_path.exists():
            with open(seed_path, 'r', encoding='utf-8') as f:
                seed_sql = f.read()
            conn.executescript(seed_sql)
        
        print(f"Banco de dados inicializado em: {db_path}")


# ============================================
# Funções auxiliares
# ============================================

def extract_hostname(url: str) -> str:
    """Extrai o hostname de uma URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower() or parsed.path.split('/')[0]
    except:
        return url.split('/')[0] if '/' in url else url


def get_or_create_link(
    url: str,
    normalized_url: str,
    db_path: str = DB_PATH
) -> int:
    """
    Busca ou cria um link no banco de dados.
    
    Args:
        url: URL original
        normalized_url: URL normalizada
        
    Returns:
        ID do link
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        # Tentar buscar link existente
        cursor.execute("SELECT id FROM links WHERE url_normalized = ?", (normalized_url,))
        row = cursor.fetchone()
        
        if row:
            return row[0]
        
        # Criar novo link
        hostname = extract_hostname(normalized_url)
        cursor.execute("""
            INSERT INTO links (url, url_normalized, hostname)
            VALUES (?, ?, ?)
        """, (url, normalized_url, hostname))
        return cursor.lastrowid


# ============================================
# Funções de inserção
# ============================================

def insert_analysis(
    url: str,
    normalized_url: str,
    score: float,
    explanation: str,
    db_path: str = DB_PATH
) -> int:
    """
    Insere uma nova análise no banco de dados.
    
    Args:
        url: URL original
        normalized_url: URL normalizada
        score: Score de risco (0-100)
        explanation: Explicação textual gerada pela IA
        
    Returns:
        ID da análise inserida
    """
    link_id = get_or_create_link(url, normalized_url, db_path)
    
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO analyses (link_id, score, explanation, last_analyzed_at)
            VALUES (?, ?, ?, datetime('now'))
        """, (link_id, score, explanation))
        return cursor.lastrowid


def insert_reputation_check(
    analysis_id: int,
    source: str,
    status: str,
    raw_json: str,
    reason: Optional[str] = None,
    elapsed_ms: Optional[int] = None,
    db_path: str = DB_PATH
) -> int:
    """
    Insere uma verificação de reputação.
    
    Args:
        analysis_id: ID da análise relacionada
        source: Fonte ('VIRUSTOTAL', 'PHISHTANK', 'GOOGLE_SAFE_BROWSING')
        status: Status ('POSITIVE', 'NEGATIVE')
        raw_json: Resposta JSON completa da API
        reason: Razão (opcional, ex: 'timeout', 'ok')
        elapsed_ms: Tempo de resposta em milissegundos
        
    Returns:
        ID da verificação inserida
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO reputation_checks 
            (analysis_id, source, status, raw_json, reason, elapsed_ms)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (analysis_id, source, status, raw_json, reason, elapsed_ms))
        return cursor.lastrowid


def insert_heuristic_hit(
    analysis_id: int,
    heuristic_code: str,
    severity: str,
    triggered: bool,
    details: Optional[str] = None,
    db_path: str = DB_PATH
) -> int:
    """
    Insere um resultado de heurística.
    
    Args:
        analysis_id: ID da análise relacionada
        heuristic_code: Código da heurística (ex: 'DOMAIN_AGE', 'PATH_LENGTH_EXCESSIVE')
        severity: Severidade ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
        triggered: Se a heurística foi acionada (True/False)
        details: Detalhes adicionais (opcional)
        
    Returns:
        ID do resultado inserido
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        # Buscar heuristic_id pelo code
        cursor.execute("SELECT id FROM heuristics WHERE code = ?", (heuristic_code,))
        heuristic_row = cursor.fetchone()
        
        if not heuristic_row:
            raise ValueError(f"Heurística com código '{heuristic_code}' não encontrada")
        
        heuristic_id = heuristic_row[0]
        triggered_int = 1 if triggered else 0
        
        cursor.execute("""
            INSERT OR REPLACE INTO heuristics_hits 
            (analysis_id, heuristic_id, severity, triggered, details)
            VALUES (?, ?, ?, ?, ?)
        """, (analysis_id, heuristic_id, severity, triggered_int, details))
        return cursor.lastrowid


def insert_ai_request(
    analysis_id: int,
    model: str,
    prompt: str,
    response: str,
    risk_score: Optional[float] = None,
    meta: Optional[str] = None,
    db_path: str = DB_PATH
) -> int:
    """
    Insere uma requisição de IA.
    
    Args:
        analysis_id: ID da análise relacionada
        model: Modelo de IA usado (ex: 'gpt-4', 'claude-3')
        prompt: Prompt enviado à IA
        response: Resposta da IA
        risk_score: Score de risco calculado pela IA (0-100, opcional)
        meta: Metadados adicionais em JSON (opcional)
        
    Returns:
        ID da requisição inserida
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO ai_requests 
            (analysis_id, model, prompt, response, risk_score, meta)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (analysis_id, model, prompt, response, risk_score, meta))
        return cursor.lastrowid


# ============================================
# Funções de consulta
# ============================================

def get_analysis_by_id(analysis_id: int, db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    """
    Busca uma análise pelo ID, incluindo informações do link.
    
    Returns:
        Dicionário com os dados da análise e do link, ou None se não encontrado
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT a.*, l.url, l.url_normalized, l.hostname
            FROM analyses a
            JOIN links l ON a.link_id = l.id
            WHERE a.id = ?
        """, (analysis_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_analysis_by_url(normalized_url: str, db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    """
    Busca a análise mais recente de uma URL normalizada.
    
    Returns:
        Dicionário com os dados da análise e do link, ou None se não encontrado
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT a.*, l.url, l.url_normalized, l.hostname
            FROM analyses a
            JOIN links l ON a.link_id = l.id
            WHERE l.url_normalized = ? 
            ORDER BY a.created_at DESC 
            LIMIT 1
        """, (normalized_url,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_reputation_checks(analysis_id: int, db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    """
    Busca todas as verificações de reputação de uma análise.
    
    Returns:
        Lista de dicionários com os dados das verificações
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM reputation_checks 
            WHERE analysis_id = ?
            ORDER BY checked_at
        """, (analysis_id,))
        return [dict(row) for row in cursor.fetchall()]


def get_heuristics_hits(analysis_id: int, db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    """
    Busca todos os resultados de heurísticas de uma análise, incluindo informações da heurística.
    
    Returns:
        Lista de dicionários com os dados das heurísticas e informações de referência
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                hh.*,
                h.code as heuristic_code,
                h.name as heuristic_name,
                h.category as heuristic_category,
                h.description as heuristic_description
            FROM heuristics_hits hh
            JOIN heuristics h ON hh.heuristic_id = h.id
            WHERE hh.analysis_id = ?
            ORDER BY hh.severity DESC, hh.created_at
        """, (analysis_id,))
        return [dict(row) for row in cursor.fetchall()]


def get_ai_requests(analysis_id: int, db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    """
    Busca todas as requisições de IA de uma análise.
    
    Returns:
        Lista de dicionários com os dados das requisições de IA
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM ai_requests 
            WHERE analysis_id = ?
            ORDER BY created_at
        """, (analysis_id,))
        return [dict(row) for row in cursor.fetchall()]


def get_full_analysis(analysis_id: int, db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    """
    Busca uma análise completa com todas as informações relacionadas.
    
    Returns:
        Dicionário com análise, link, verificações de reputação, heurísticas e requisições de IA
    """
    analysis = get_analysis_by_id(analysis_id, db_path)
    if not analysis:
        return None
    
    return {
        **analysis,
        'reputation_checks': get_reputation_checks(analysis_id, db_path),
        'heuristics_hits': get_heuristics_hits(analysis_id, db_path),
        'ai_requests': get_ai_requests(analysis_id, db_path)
    }


# ============================================
# Funções de estatísticas
# ============================================

def get_analyses_stats(db_path: str = DB_PATH) -> Dict[str, Any]:
    """
    Retorna estatísticas do banco de dados.
    
    Returns:
        Dicionário com estatísticas
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        
        stats = {}
        
        # Total de análises
        cursor.execute("SELECT COUNT(*) FROM analyses")
        stats['total_analyses'] = cursor.fetchone()[0]
        
        # Média de score
        cursor.execute("SELECT AVG(score) FROM analyses")
        stats['avg_score'] = cursor.fetchone()[0] or 0
        
        # Total de verificações de reputação
        cursor.execute("SELECT COUNT(*) FROM reputation_checks")
        stats['total_reputation_checks'] = cursor.fetchone()[0]
        
        # Total de heurísticas acionadas
        cursor.execute("SELECT COUNT(*) FROM heuristics_hits WHERE triggered = 1")
        stats['total_heuristics_triggered'] = cursor.fetchone()[0]
        
        # Total de links únicos
        cursor.execute("SELECT COUNT(*) FROM links")
        stats['total_links'] = cursor.fetchone()[0]
        
        # Total de requisições de IA
        cursor.execute("SELECT COUNT(*) FROM ai_requests")
        stats['total_ai_requests'] = cursor.fetchone()[0]
        
        return stats


def clear_all_data(db_path: str = DB_PATH) -> None:
    """
    Limpa todos os dados das tabelas (exceto heuristics que são de referência).
    Mantém a estrutura das tabelas intacta.
    
    Atenção: Esta função apaga TODOS os dados de análise!
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        
        # Ordem importante devido às foreign keys
        # Primeiro apaga dados dependentes
        cursor.execute("DELETE FROM ai_requests")
        cursor.execute("DELETE FROM heuristics_hits")
        cursor.execute("DELETE FROM reputation_checks")
        cursor.execute("DELETE FROM analyses")
        cursor.execute("DELETE FROM links")
        
        # Reseta os contadores AUTOINCREMENT
        cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('links', 'analyses', 'reputation_checks', 'heuristics_hits', 'ai_requests')")
        
        print(" Todas as tabelas de dados foram limpas (heuristics mantidas)")

