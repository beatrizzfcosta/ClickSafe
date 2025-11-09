#!/usr/bin/env python3
import json
import os
import sys
import asyncio
from pathlib import Path

# Adiciona o diretório backend ao path para importar services
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from services.vt import check_vt

# Carrega .env.local se existir
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent.parent / '.env.local'
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass

async def main():
    if len(sys.argv) < 2:
        print("uso: python services/vt/test_vt_cli.py <URL>")
        print("     ou: python -m services.vt.test_vt_cli <URL>")
        return
    
    url = sys.argv[1]
    
    try:
        # Usa a função check_vt que retorna formato padronizado
        result = await check_vt(url)
        
        # Exibe resultado em JSON
        print(json.dumps(result, indent=2, ensure_ascii=False))
        
    except Exception as e:
        print(f"Erro inesperado: {type(e).__name__}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())

