#!/usr/bin/env python3
"""
Script para inicializar o banco de dados ClickSafe.
Execute este script uma vez para criar todas as tabelas.
"""
import sys
from storage.db import init_db, DB_PATH


def main():
    """Inicializa o banco de dados."""
    print(f"Inicializando banco de dados ClickSafe...")
    print(f"Localização: {DB_PATH}")
    
    try:
        init_db()
        print("\nBanco de dados inicializado com sucesso!")
        print("\nTabelas criadas:")
        print("   - analyses")
        print("   - reputation_checks")
        print("   - heuristics_hits")
    except Exception as e:
        print(f"\nErro ao inicializar banco de dados: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

