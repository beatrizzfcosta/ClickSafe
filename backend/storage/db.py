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
    with open(schema_path, 'r', encoding='utf-8') as f:
        schema_sql = f.read()
    
    with get_db(db_path) as conn:
        conn.executescript(schema_sql)
        print(f"Banco de dados inicializado em: {db_path}")


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
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO analyses (url, normalized_url, score, explanation)
            VALUES (?, ?, ?, ?)
        """, (url, normalized_url, score, explanation))
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
    type: str,
    severity: str,
    status: str,
    details: Optional[str] = None,
    db_path: str = DB_PATH
) -> int:
    """
    Insere um resultado de heurística.
    
    Args:
        analysis_id: ID da análise relacionada
        type: Tipo da heurística (ex: 'DOMAIN_AGE', 'PATH_LENGTH_EXCESSIVE')
        severity: Severidade ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
        status: Status ('TRUE', 'FALSE')
        details: Detalhes adicionais (opcional)
        
    Returns:
        ID do resultado inserido
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO heuristics_hits 
            (analysis_id, type, severity, status, details)
            VALUES (?, ?, ?, ?, ?)
        """, (analysis_id, type, severity, status, details))
        return cursor.lastrowid


# ============================================
# Funções de consulta
# ============================================

def get_analysis_by_id(analysis_id: int, db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    """
    Busca uma análise pelo ID.
    
    Returns:
        Dicionário com os dados da análise ou None se não encontrado
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_analysis_by_url(normalized_url: str, db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    """
    Busca a análise mais recente de uma URL normalizada.
    
    Returns:
        Dicionário com os dados da análise ou None se não encontrado
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM analyses 
            WHERE normalized_url = ? 
            ORDER BY created_at DESC 
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
    Busca todos os resultados de heurísticas de uma análise.
    
    Returns:
        Lista de dicionários com os dados das heurísticas
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM heuristics_hits 
            WHERE analysis_id = ?
            ORDER BY severity DESC, created_at
        """, (analysis_id,))
        return [dict(row) for row in cursor.fetchall()]


def get_full_analysis(analysis_id: int, db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    """
    Busca uma análise completa com todas as informações relacionadas.
    
    Returns:
        Dicionário com análise, verificações de reputação e heurísticas
    """
    analysis = get_analysis_by_id(analysis_id, db_path)
    if not analysis:
        return None
    
    return {
        **analysis,
        'reputation_checks': get_reputation_checks(analysis_id, db_path),
        'heuristics_hits': get_heuristics_hits(analysis_id, db_path)
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
        cursor.execute("SELECT COUNT(*) FROM heuristics_hits WHERE status = 'TRUE'")
        stats['total_heuristics_triggered'] = cursor.fetchone()[0]
        
        return stats

