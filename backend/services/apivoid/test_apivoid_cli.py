import asyncio
import json
import os
import sys
from pathlib import Path

#Ajusta o sys.path para permitir imports corretos
BASE_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE_DIR))

#Carrega .env.local se existir
try:
    from dotenv import load_dotenv
    env_path = BASE_DIR / ".env.local"
    if env_path.exists():
        load_dotenv(env_path)
except Exception:
    pass

from services.apivoid.apivoidrep import check_apivoid


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
