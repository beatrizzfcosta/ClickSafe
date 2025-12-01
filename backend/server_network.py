"""
Servidor FastAPI para o ClickSafe - Versão para Rede Local.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict
from typing import Optional
import socket
from pathlib import Path
from storage.db import init_db, get_analysis_by_url, get_full_analysis, get_analyses_stats
from app import analyze_url

def get_local_ip():
    """Obtém o IP da máquina na rede local"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


LOCAL_IP = get_local_ip()

# Configurar caminho do frontend buildado
BACKEND_DIR = Path(__file__).parent
FRONTEND_DIR = BACKEND_DIR.parent / "frontend"
FRONTEND_DIST = FRONTEND_DIR / "dist"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager para inicializar o banco de dados"""
    # Startup
    init_db()
    print(f"\n{'='*60}")
    print(f"ClickSafe Server - Modo Rede Local")
    print(f"{'='*60}")
    print(f"IP Local: {LOCAL_IP}")
    print(f"Porta: 8000")
    print(f"Acesse em: http://{LOCAL_IP}:8000")
    if FRONTEND_DIST.exists():
        print(f"Frontend: http://{LOCAL_IP}:8000")
    else:
        print(f"Frontend: Não encontrado. Execute 'npm run build' no diretório frontend/")
    print(f"API Docs: http://{LOCAL_IP}:8000/docs")
    print(f"{'='*60}\n")
    yield
    # Shutdown (se necessário no futuro)


app = FastAPI(title="ClickSafe API - Network Mode", version="1.0.0", lifespan=lifespan)

# Permitir todas as origens (para desenvolvimento em rede local)
# Em produção, você deve especificar as origens exatas
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if FRONTEND_DIST.exists() and (FRONTEND_DIST / "index.html").exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")
    
    # Rota para servir o frontend (SPA - Single Page Application)
    @app.get("/")
    async def serve_frontend():
        return FileResponse(FRONTEND_DIST / "index.html")
    
    @app.get("/{full_path:path}")
    async def serve_frontend_routes(full_path: str):
        if full_path.startswith("api/") or full_path.startswith("docs") or full_path == "openapi.json":
            raise HTTPException(status_code=404, detail="Not found")
        file_path = FRONTEND_DIST / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(FRONTEND_DIST / "index.html")

class URLRequest(BaseModel):
    url: str


class URLResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")  # Permite campos extras do banco de dados
    
    id: int
    url: str
    normalized_url: Optional[str] = None
    score: float
    explanation: Optional[str] = None
    reputation_checks: list = []
    heuristic_hits: list = []
    ai_requests: list = []


@app.post("/api/analyze", response_model=URLResponse)
async def analyze_url_endpoint(request: URLRequest, http_request: Request):
    try:
        print(f"\n[API] Recebida requisição para analisar: {request.url}")
        print(f"[API] Origin: {http_request.headers.get('origin', 'N/A')}")
        print(f"[API] User-Agent: {http_request.headers.get('user-agent', 'N/A')[:50]}...")
        
        result = await analyze_url(request.url)
        print(f"[API] Análise concluída. Preparando resposta...")
        print(f"[API] Campos no resultado: {list(result.keys())}")
        
        # Mapear campos para o formato esperado
        if 'heuristics_hits' in result:
            result['heuristic_hits'] = result.pop('heuristics_hits')
        if 'normalized_url' not in result and 'url_normalized' in result:
            result['normalized_url'] = result.pop('url_normalized')
        
        # Garantir que todos os campos obrigatórios existem
        if 'heuristic_hits' not in result:
            result['heuristic_hits'] = []
        if 'reputation_checks' not in result:
            result['reputation_checks'] = []
        if 'ai_requests' not in result:
            result['ai_requests'] = []
        
        # Remover campos extras que não estão no modelo (link_id, hostname, etc)
        # Manter apenas os campos esperados pelo URLResponse
        allowed_fields = {'id', 'url', 'normalized_url', 'score', 'explanation', 
                         'reputation_checks', 'heuristic_hits', 'ai_requests'}
        filtered_result = {k: v for k, v in result.items() if k in allowed_fields}
        
        print(f"[API] Retornando resposta com {len(filtered_result.get('heuristic_hits', []))} heurísticas")
        print(f"[API] Campos filtrados: {list(filtered_result.keys())}")
        response = URLResponse(**filtered_result)
        print(f"[API] Resposta criada com sucesso")
        return response
    except HTTPException:
        # Re-raise HTTP exceptions (já são erros HTTP apropriados)
        raise
    except Exception as e:
        import traceback
        error_detail = f"Erro ao analisar URL: {str(e)}\n{traceback.format_exc()}"
        print(f"\n[API] ERRO: {error_detail}")
        raise HTTPException(status_code=500, detail=error_detail)


@app.api_route("/", methods=["GET"], include_in_schema=False)
async def root_fallback():
    """Fallback se o frontend não estiver buildado"""
    if not FRONTEND_DIST.exists():
        return {
            "message": "ClickSafe API - Network Mode",
            "version": "1.0.0",
            "local_ip": LOCAL_IP,
            "endpoints": {
                "analyze": "/api/analyze",
                "health": "/api/health",
                "analysis_by_id": "/api/analysis/{id}",
                "analysis_by_url": "/api/analysis/url/{url}",
                "stats": "/api/stats",
                "docs": "/docs"
            },
            "network_access": f"http://{LOCAL_IP}:8000",
            "note": "Frontend não encontrado. Execute 'npm run build' no diretório frontend/"
        }


@app.get("/api/health")
async def health_check():
    """
    Endpoint de health check com informações de rede.
    """
    return {
        "status": "ok",
        "local_ip": LOCAL_IP,
        "message": f"Servidor acessível em http://{LOCAL_IP}:8000",
        "mode": "network"
    }


@app.get("/api/analysis/{analysis_id}")
async def get_analysis(analysis_id: int):
    """
    Busca uma análise pelo ID.
    """
    analysis = get_full_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Análise não encontrada")
    return analysis


@app.get("/api/analysis/url/{url:path}")
async def get_analysis_by_url_endpoint(url: str):
    """
    Busca a análise mais recente de uma URL.
    """
    # Adicionar http:// se não tiver protocolo
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    analysis = get_analysis_by_url(url)
    if not analysis:
        raise HTTPException(status_code=404, detail="Análise não encontrada para esta URL")
    
    return get_full_analysis(analysis['id'])




