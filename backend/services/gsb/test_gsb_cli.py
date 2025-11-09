#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

# Adiciona o diretório backend ao path para importar services
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from services.gsb import SafeBrowsing, SafeBrowsingInvalidApiKey, SafeBrowsingPermissionDenied, SafeBrowsingWeirdError

# Carrega .env.local se existir
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent.parent / '.env.local'
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass

def main():
    if len(sys.argv) < 2:
        print("uso: python services/gsb/test_gsb_cli.py <URL>")
        print("     ou: python -m services.gsb.test_gsb_cli <URL>")
        return
    
    # Obtém a API key
    api_key = os.getenv("GSB_API_KEY", "")
    if not api_key:
        print("Erro: GSB_API_KEY não configurada!")
        print("Configure a variável de ambiente GSB_API_KEY ou adicione no arquivo .env.local")
        sys.exit(1)
    
    url = sys.argv[1]
    
    try:
        # Cria instância do SafeBrowsing
        sb = SafeBrowsing(api_key)
        
        # Verifica a URL
        result = sb.lookup_url(url)
        
        # Exibe resultado em JSON
        print(json.dumps(result, indent=2, ensure_ascii=False))
        
    except SafeBrowsingInvalidApiKey:
        print("Erro: API key inválida!")
        sys.exit(1)
    except SafeBrowsingPermissionDenied as e:
        print(f"Erro: Permissão negada - {e}")
        sys.exit(1)
    except SafeBrowsingWeirdError as e:
        print(f"Erro: {e.message}")
        sys.exit(1)
    except Exception as e:
        print(f"Erro inesperado: {type(e).__name__}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

