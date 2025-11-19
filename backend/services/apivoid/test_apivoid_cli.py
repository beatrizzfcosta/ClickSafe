import asyncio
import json
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

#Ajusta o sys.path para permitir imports corretos
ROOT_DIR = Path(__file__).resolve().parents[3]  
sys.path.insert(0, str(ROOT_DIR))

#Carrega .env.local se existir
env_path = ROOT_DIR / ".env.local"

print(f"DEBUG: env_path = {env_path}, exists = {env_path.exists()}")

if env_path.exists():
    load_dotenv(env_path)
else:
    print("Aviso: .env.local não encontrado no root do projeto.")

from backend.services.apivoid.apivoidrep import check_apivoid

async def main():
    if len(sys.argv) < 2:
        print("Uso: python backend/services/apivoid/test_apivoid_cli.py <URL>")
        sys.exit(1)

    url = sys.argv[1]
    api_key = os.getenv("APIVOID_API_KEY")

    if not api_key:
        print("Erro: APIVOID_API_KEY não configurada.")
        print("Adiciona ao teu .env.local, exemplo:")
        print("  APIVOID_API_KEY=YOUR_KEY_HERE")
        sys.exit(1)

    print(f"\nTeste APIVoid para: {url}\n")
    result = await check_apivoid(url)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
