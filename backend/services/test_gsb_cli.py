#!/usr/bin/env python3
import asyncio
import json
import sys
from pathlib import Path

# Adiciona o diretório backend ao path para importar services
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.reputation import consolidate_reputation

async def main():
    if len(sys.argv) < 2:
        print("uso: python services/test_gsb_cli.py <URL>")
        print("     ou: python -m services.test_gsb_cli <URL>")
        return
    url = sys.argv[1]
    rep = await consolidate_reputation(url)
    print(json.dumps(rep, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    asyncio.run(main())
