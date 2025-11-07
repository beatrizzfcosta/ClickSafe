#!/usr/bin/env python3
"""
Script para inicializar o banco de dados ClickSafe.
Execute este script para criar todas as tabelas (apaga banco antigo se existir).
"""
import sys
import os
from storage.db import init_db, DB_PATH


def main():
    """Inicializa o banco de dados."""
    print(f"Inicializando banco de dados ClickSafe...")
    print(f"Localização: {DB_PATH}")
    
    # Remove banco antigo se existir
    if os.path.exists(DB_PATH):
        print(f"\nBanco de dados existente encontrado. Removendo...")
        os.remove(DB_PATH)
        print("   ✓ Banco antigo removido")
    
    try:
        init_db()
        print("\nBanco de dados inicializado com sucesso!")
        print("\nTabelas criadas:")
        print("   - links")
        print("   - analyses")
        print("   - reputation_checks")
        print("   - heuristics")
        print("   - heuristics_hits")
        print("   - ai_requests")
        print("\nTabela 'heuristics' populada com dados iniciais.")
    except Exception as e:
        print(f"\nErro ao inicializar banco de dados: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

