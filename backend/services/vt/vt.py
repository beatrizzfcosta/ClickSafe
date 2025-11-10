
import os
import time
import requests
from pathlib import Path
from typing import Dict
from json.decoder import JSONDecodeError

# Carrega .env.local se existir
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent.parent / '.env.local'
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass


class VirustotalException(Exception):
    """Exceção base para todos os erros do VirusTotal."""
    pass

# Alias para compatibilidade
VirustotalError = VirustotalException


class VirustotalInvalidApiKey(VirustotalException):
    """Erro lançado quando a chave da API fornecida é inválida ou não foi configurada."""
    def __init__(self):
        Exception.__init__(self, "Invalid API key for VirusTotal")


class VirustotalPermissionDenied(VirustotalException):
    """Erro lançado quando o acesso à API é negado (ex: chave sem permissão adequada)."""
    def __init__(self, detail):
        Exception.__init__(self, detail)


class VirustotalRateLimit(VirustotalException):
    """Erro lançado quando o limite de requisições por minuto é excedido."""
    def __init__(self, detail):
        Exception.__init__(self, detail)


class VirustotalWeirdError(VirustotalException):
    """Erro genérico para outros problemas inesperados com a API."""
    def __init__(self, code, status, message):
        self.message = "%s(%s): %s" % (status, str(code), message)
        Exception.__init__(self, self.message)


class Virustotal(object):
    """ Classe responsável por consultar a API do VirusTotal para análise de URLs. """

    def __init__(self, api_key: str, 
                 api_url: str = 'https://www.virustotal.com/api/v3',
                 timeout: float = 10.0):
        """ Inicializa o cliente VirusTotal. """
        self.api_key = api_key
        self.api_url = api_url.rstrip('/')
        self.timeout = timeout
        self.headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "virustotal-python",
            "x-apikey": self.api_key,  # API v3 usa header x-apikey
        }

    def _handle_error_response(self, response: requests.Response):
        """
        Trata erros HTTP retornados pela API do VirusTotal.
        
        Converte códigos de status HTTP em exceções específicas do domínio.
        
        VirustotalInvalidApiKey: Se a chave da API for inválida (400, 401)
        VirustotalPermissionDenied: Se o acesso for negado (403)
        VirustotalRateLimit: Se o limite de requisições for excedido (429)
        VirustotalWeirdError: Para outros erros HTTP
        """
        status_code = response.status_code
        
        if status_code in (400, 401):
            # 400 ou 401 = chave inválida
            error_data = response.json().get('error', {})
            error_message = error_data.get('message', 'Bad request')
            if 'API key' in error_message or 'Invalid' in error_message:
                raise VirustotalInvalidApiKey()
            else:
                raise VirustotalWeirdError(
                    error_data.get('code', status_code),
                    'BadRequest',
                    error_message
                )
        elif status_code == 403:
            # 403 = permissão negada
            error_data = response.json().get('error', {})
            raise VirustotalPermissionDenied(
                error_data.get('message', 'Permission denied')
            )
        elif status_code == 429:
            # 429 = rate limit excedido
            error_data = response.json().get('error', {})
            raise VirustotalRateLimit(
                error_data.get('message', 'Rate limit exceeded')
            )
        else:
            # Outros erros
            error_data = response.json().get('error', {})
            raise VirustotalWeirdError(
                status_code,
                error_data.get('status', 'Unknown'),
                error_data.get('message', 'Unknown error')
            )

    def analyze_url(self, url: str) -> Dict:
        """
        Analisa uma URL usando a API do VirusTotal.
        
        Fluxo de trabalho:
        1. Submete a URL para análise (POST /urls)
        2. Aguarda a análise processar (2 segundos)
        3. Consulta o resultado da análise (GET /analyses/{id})
        4. Se disponível, consulta os dados completos da URL (GET /urls/{id})
        
        
        VirustotalInvalidApiKey: Se a chave da API for inválida
        VirustotalPermissionDenied: Se o acesso for negado
        VirustotalRateLimit: Se o limite de requisições for excedido
        VirustotalWeirdError: Para outros erros
        """
        submit_endpoint = f"{self.api_url}/urls"
        
        try:
            # Passo 1: Submete a URL para análise
            submit_response = requests.post(
                submit_endpoint,
                headers=self.headers,
                data={"url": url},
                timeout=self.timeout
            )
            
            if submit_response.status_code != 200:
                self._handle_error_response(submit_response)
            
            submit_data = submit_response.json()
            analysis_data = submit_data.get('data', {})
            analysis_id = analysis_data.get('id', '')
            analysis_type = analysis_data.get('type', '')
            
            # Se a resposta já for um objeto URL, retorna diretamente
            if analysis_type == 'url':
                return submit_data
            
            # Passo 2: Se for uma análise, consulta o resultado
            if analysis_id and analysis_type == 'analysis':
                analysis_endpoint = f"{self.api_url}/analyses/{analysis_id}"
                
                # Aguarda a análise processar (pode levar alguns segundos)
                time.sleep(2)
                
                analysis_response = requests.get(
                    analysis_endpoint,
                    headers=self.headers,
                    timeout=self.timeout
                )
                
                if analysis_response.status_code == 200:
                    analysis_result = analysis_response.json()
                    analysis_attrs = analysis_result.get('data', {}).get('attributes', {})
                    
                    # Passo 3: Tenta obter dados completos da URL se disponível
                    url_id = analysis_attrs.get('url_id')
                    if url_id:
                        url_endpoint = f"{self.api_url}/urls/{url_id}"
                        url_response = requests.get(
                            url_endpoint,
                            headers=self.headers,
                            timeout=self.timeout
                        )
                        
                        if url_response.status_code == 200:
                            return url_response.json()
                    
                    # Se não conseguir dados da URL, retorna a análise
                    return analysis_result
            
            # Fallback: retorna dados da submissão
            return submit_data
                
        except requests.exceptions.Timeout:
            raise VirustotalWeirdError(0, 'Timeout', 'Request timeout')
        except requests.exceptions.RequestException as e:
            raise VirustotalWeirdError(0, 'RequestException', str(e))


async def check_vt(url: str, timeout: int = 10) -> Dict:
    """
    Verifica uma URL no VirusTotal e retorna resultado padronizado.
    
    Esta é a função principal para uso no sistema. Ela:
    - Verifica se a API key está configurada
    - Analisa a URL usando a API do VirusTotal
    - Processa as estatísticas de detecção
    - Retorna um formato padronizado compatível com outros serviços (GSB)
    
    Formato de retorno:
        {
            "status": "POSITIVE" | "NEGATIVE" | "UNKNOWN",
            "reason": "ok" | "no_key" | "error:...",
            "raw": {
                "stats": {
                    "malicious": int,
                    "suspicious": int,
                    "harmless": int,
                    "undetected": int,
                    "total_engines": int
                },
                "malicious": int,
                "suspicious": int,
                "harmless": int,
                "undetected": int
            },
            "elapsed_ms": int
        }
    
    Status:
        - POSITIVE: URL detectada como maliciosa ou suspeita
        - NEGATIVE: URL verificada como segura (sem detecções maliciosas)
        - UNKNOWN: Não foi possível determinar (sem API key, erro, ou análise incompleta)

    """
    start_time = time.time()
    
    # Verifica se a API key está configurada
    api_key = os.getenv("VT_API_KEY", "")
    if not api_key:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "UNKNOWN",
            "reason": "no_key",
            "raw": {},
            "elapsed_ms": elapsed_ms
        }
    
    try:
        # Cria cliente e analisa URL
        vt = Virustotal(api_key, timeout=timeout)
        result = vt.analyze_url(url)
        
        elapsed_ms = int((time.time() - start_time) * 1000)
        
        # Extrai dados da resposta
        data = result.get('data', {})
        data_type = data.get('type', '')
        attributes = data.get('attributes', {})
        
        # Obtém estatísticas de detecção
        # A API retorna dois formatos diferentes:
        # - Tipo "analysis": estatísticas em attributes.stats
        # - Tipo "url": estatísticas em attributes.last_analysis_stats
        if data_type == 'analysis':
            stats = attributes.get('stats', {})
            analysis_status = attributes.get('status', '')
            
            # Se a análise não estiver completa, retorna UNKNOWN
            if analysis_status != 'completed':
                return {
                    "status": "UNKNOWN",
                    "reason": f"analysis_{analysis_status}",
                    "raw": {
                        "stats": stats,
                        "message": f"Analysis status: {analysis_status}"
                    },
                    "elapsed_ms": elapsed_ms
                }
        else:
            # Tipo "url" ou outro
            stats = attributes.get('last_analysis_stats', {})
        
        # Se não houver estatísticas, retorna UNKNOWN
        if not stats:
            return {
                "status": "UNKNOWN",
                "reason": "no_data",
                "raw": {"stats": {}},
                "elapsed_ms": elapsed_ms
            }
        
        # Extrai contadores de detecção
        harmless = stats.get('harmless', 0)
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        undetected = stats.get('undetected', 0)
        total_engines = harmless + malicious + suspicious + undetected
        
        # Determina status baseado nas detecções
        if malicious > 0 or suspicious > 0:
            # Há detecções maliciosas ou suspeitas
            status = "POSITIVE"
        elif total_engines > 0 and (harmless > 0 or undetected > 0):
            # Há análises e nenhuma maliciosa/suspeita = seguro
            status = "NEGATIVE"
        else:
            # Sem dados suficientes
            status = "UNKNOWN"
        
        # Retorna resultado padronizado
        return {
            "status": status,
            "reason": "ok",
            "raw": {
                "stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "total_engines": total_engines
                },
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected
            },
            "elapsed_ms": elapsed_ms
        }
        
    except VirustotalInvalidApiKey:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "UNKNOWN",
            "reason": "error:VirustotalInvalidApiKey",
            "raw": {},
            "elapsed_ms": elapsed_ms
        }
    except VirustotalPermissionDenied as e:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "UNKNOWN",
            "reason": f"error:VirustotalPermissionDenied:{str(e)}",
            "raw": {},
            "elapsed_ms": elapsed_ms
        }
    except VirustotalRateLimit as e:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "UNKNOWN",
            "reason": f"error:VirustotalRateLimit:{str(e)}",
            "raw": {},
            "elapsed_ms": elapsed_ms
        }
    except VirustotalWeirdError as e:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "UNKNOWN",
            "reason": f"error:VirustotalWeirdError:{e.message}",
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
