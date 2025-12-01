"""
Servidor FastAPI para o ClickSafe - API REST para análise de URLs.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict
from typing import Optional
import asyncio
from storage.db import init_db
from app import analyze_url


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager para inicializar o banco de dados"""
    # Startup
    init_db()
    yield
    # Shutdown (se necessário no futuro)


app = FastAPI(title="ClickSafe API", version="1.0.0", lifespan=lifespan)

# Configurar CORS para permitir requisições do frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],  # Vite default port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
async def analyze_url_endpoint(request: URLRequest):
    """
    Analisa uma URL e retorna o resultado completo.
    """
    try:
        result = await analyze_url(request.url)
        # Mapear heuristics_hits para heuristic_hits para compatibilidade
        if 'heuristics_hits' in result:
            result['heuristic_hits'] = result.pop('heuristics_hits')
        # Garantir que normalized_url existe
        if 'normalized_url' not in result and 'url_normalized' in result:
            result['normalized_url'] = result.pop('url_normalized')
        return URLResponse(**result)
    except Exception as e:
        import traceback
        error_detail = f"Erro ao analisar URL: {str(e)}\n{traceback.format_exc()}"
        raise HTTPException(status_code=500, detail=error_detail)


@app.get("/")
async def root():
    """
    Endpoint raiz - redireciona para a documentação da API.
    """
    return {
        "message": "ClickSafe API",
        "version": "1.0.0",
        "endpoints": {
            "analyze": "/api/analyze",
            "health": "/api/health",
            "docs": "/docs"
        }
    }


@app.get("/api/health")
async def health_check():
    """
    Endpoint de health check.
    """
    return {"status": "ok"}

