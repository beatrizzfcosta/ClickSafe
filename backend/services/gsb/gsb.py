import json
import os
import time
import requests
from pathlib import Path
from typing import Dict, Optional
from .about import __version__

# Carrega .env.local se existir
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent.parent / '.env.local'
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass  


class SafeBrowsingException(Exception):
    """Exceção base genérica para erros do Safe Browsing."""
    pass


class SafeBrowsingInvalidApiKey(SafeBrowsingException):
    """Erro lançado quando a chave da API fornecida é inválida."""
    def __init__(self):
        Exception.__init__(self, "Invalid API key for Google Safe Browsing")


class SafeBrowsingPermissionDenied(SafeBrowsingException):
    """Erro lançado quando o acesso à API é negado (ex: chave sem permissão)."""
    def __init__(self, detail):
        Exception.__init__(self, detail)


class SafeBrowsingWeirdError(SafeBrowsingException):
    """Erro genérico para outros problemas inesperados com a API."""
    def __init__(self, code, status, message):
        # Monta uma mensagem mais detalhada
        self.message = "%s(%i): %s" % (status, code, message)
        Exception.__init__(self, self.message)


def chunks(lst, n):
    """
    Divide uma lista em blocos (sublistas) de tamanho n.

    Exemplo:
        chunks([1, 2, 3, 4, 5], 2) -> [[1, 2], [3, 4], [5]]
    """
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


class SafeBrowsing(object):
    """
    Classe responsável por consultar a API do Google Safe Browsing.

    Parâmetros:
        key (str): chave da API (GSB API key)
        api_url (str): URL base da API (padrão da versão 4)
    """

    def __init__(self, key,
                 api_url='https://safebrowsing.googleapis.com/v4/threatMatches:find'):
        self.api_key = key
        self.api_url = api_url


    def lookup_urls(self, urls, platforms=["ANY_PLATFORM"]):
        """
        Verifica múltiplas URLs na API do Google Safe Browsing.

        Argumentos:
            urls (list[str]): lista de URLs a verificar
            platforms (list[str]): lista de plataformas a considerar (padrão: "ANY_PLATFORM")

        Retorna:
            dict: dicionário com resultados no formato:
                  { "url": {"malicious": bool, ...}, ... }
        """

        results = {}

        # Divide as URLs em blocos de 25 (limite máximo da API por requisição)
        for urll in chunks(urls, 25):
            # Monta o corpo (payload) da requisição
            safe_browsing_request = {
                "client": {
                    "clientId": "pysafebrowsing",       # nome do cliente
                    "clientVersion": __version__         # versão atual do pacote
                },
                "threatInfo": {
                    "threatTypes": [                    # tipos de ameaças a verificar
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "THREAT_TYPE_UNSPECIFIED",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": platforms,          # plataformas alvo
                    "threatEntryTypes": ["URL"],         # tipo de entrada (URL)
                    "threatEntries": [{'url': u} for u in urll]  # lista de URLs
                }
            }

            headers = {'Content-type': 'application/json'}

            # Faz o POST para a API do Google Safe Browsing
            r = requests.post(
                self.api_url,
                data=json.dumps(safe_browsing_request),           # converte o corpo para JSON
                params={'key': self.api_key},    # inclui a chave da API nos parâmetros
                headers=headers
            )

            # Tratamento de resposta
            if r.status_code == 200:
                # 200 = sucesso
                data = r.json()
                matches_data = data.get('matches', [])
                
                if not matches_data:
                    # Nenhuma ameaça encontrada → todas seguras
                    results.update(dict([(u, {"malicious": False}) for u in urll]))
                else:
                    # Existem correspondências de ameaças ("matches")
                    for url in urll:
                        # Filtra os matches correspondentes à URL atual
                        matches = [match for match in matches_data
                                   if match.get('threat', {}).get('url') == url]

                        if len(matches) > 0:
                            # Caso a URL tenha sido marcada como maliciosa
                            cache_durations = [b.get("cacheDuration") for b in matches if b.get("cacheDuration")]
                            result = {
                                'malicious': True,
                                # Lista de plataformas afetadas (sem duplicatas)
                                'platforms': list(set([b.get('platformType', '') for b in matches])),
                                # Tipos de ameaças encontrados (sem duplicatas)
                                'threats': list(set([b.get('threatType', '') for b in matches])),
                            }
                            # Duração mínima do cache (se disponível)
                            if cache_durations:
                                result['cache'] = min(cache_durations)
                            results[url] = result
                        else:
                            # URL sem ameaças detectadas
                            results[url] = {"malicious": False}

            else:

                # Tratamento de erros HTTP
                if r.status_code == 400:
                    print(r.json())
                    # Erro 400: requisição inválida (ex: chave incorreta)
                    if r.json()['error']['message'] == 'API key not valid. Please pass a valid API key.':
                        raise SafeBrowsingInvalidApiKey()
                    else:
                        raise SafeBrowsingWeirdError(
                            r.json()['error']['code'],
                            r.json()['error']['status'],
                            r.json()['error']['message'],
                        )
                elif r.status_code == 403:
                    # Erro 403: acesso negado (sem permissão)
                    raise SafeBrowsingPermissionDenied(r.json()['error']['message'])
                else:
                    # Outros erros HTTP genéricos
                    raise SafeBrowsingWeirdError(r.status_code, "", "")

        return results

    # Método: lookup_url

    def lookup_url(self, url, platforms=["ANY_PLATFORM"]):
        """
        Consulta uma única URL na API (modo simples).

        Argumentos:
            url (str): URL a verificar
            platforms (list[str]): plataformas alvo

        Retorna:
            dict: resultado no formato {"malicious": bool, ...}
        """
        r = self.lookup_urls([url], platforms=platforms)
        return r[url]


async def check_gsb(url: str, timeout: int = 3) -> Dict:
    """
    Função assíncrona para verificar URL no Google Safe Browsing.
    
    Retorna formato padronizado:
    {
        "status": "POSITIVE" | "NEGATIVE" | "UNKNOWN",
        "reason": "ok" | "no_key" | "timeout" | "error:...",
        "raw": {...},  # Resposta completa da API
        "elapsed_ms": int  # Tempo de resposta em milissegundos
    }
    
    Args:
        url: URL a verificar
        timeout: Timeout em segundos (padrão: 3)
        
    Returns:
        Dicionário com resultado padronizado
    """
    start_time = time.time()
    
    # Verifica se a API key está configurada
    api_key = os.getenv("GSB_API_KEY", "")
    if not api_key:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "UNKNOWN",
            "reason": "no_key",
            "raw": {},
            "elapsed_ms": elapsed_ms
        }
    
    try:
        # Cria instância do SafeBrowsing
        sb = SafeBrowsing(api_key)
        
        # Executa a verificação (síncrona, mas em contexto assíncrono)
        # Em produção, pode ser melhor usar httpx para requisições assíncronas
        result = sb.lookup_url(url)
        
        elapsed_ms = int((time.time() - start_time) * 1000)
        
        # Converte resultado para formato padronizado
        if result.get("malicious", False):
            status = "POSITIVE"
        else:
            status = "NEGATIVE"
        
        return {
            "status": status,
            "reason": "ok",
            "raw": result,
            "elapsed_ms": elapsed_ms
        }
        
    except SafeBrowsingInvalidApiKey:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "UNKNOWN",
            "reason": "error:SafeBrowsingInvalidApiKey",
            "raw": {},
            "elapsed_ms": elapsed_ms
        }
    except SafeBrowsingPermissionDenied as e:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "UNKNOWN",
            "reason": f"error:SafeBrowsingPermissionDenied:{str(e)}",
            "raw": {},
            "elapsed_ms": elapsed_ms
        }
    except SafeBrowsingWeirdError as e:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "UNKNOWN",
            "reason": f"error:SafeBrowsingWeirdError:{e.message}",
            "raw": {},
            "elapsed_ms": elapsed_ms
        }
    except Exception as e:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "UNKNOWN",
            "reason": f"error:{type(e).__name__}:{str(e)}",
            "raw": {},
            "elapsed_ms": elapsed_ms
        }
