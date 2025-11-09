#!/usr/bin/env python3
import asyncio
import json
import sys
from pathlib import Path

# Adiciona o diretório backend ao path para importar services
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from services.gsb import check_gsb

async def main():
    if len(sys.argv) < 2:
        print("uso: python services/gsb/test_gsb_cli.py <URL>")
        print("     ou: python -m services.gsb.test_gsb_cli <URL>")
        return
    url = sys.argv[1]
    result = await check_gsb(url)
    print(json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    asyncio.run(main())

