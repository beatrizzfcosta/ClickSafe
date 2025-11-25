# Módulo de Banco de Dados - ClickSafe

Este módulo gerencia todas as operações de banco de dados SQLite para o ClickSafe.

## Inicialização

### 1. Inicializar o banco de dados (primeira vez)

```bash
cd backend
python init_db.py
```

Isso criará o arquivo `clicksafe.db` (ou o caminho especificado em `CLICKSAFE_DB_PATH`) com todas as tabelas e populará a tabela `heuristics` com os dados iniciais.

**Nota:** Se já existir um banco de dados, ele será removido e recriado do zero.

## Uso Básico

### Inserir uma análise

```python
from storage.db import insert_analysis

analysis_id = insert_analysis(
    url="https://example.com/path",
    normalized_url="https://example.com/path",
    score=75.5,
    explanation="URL apresenta riscos moderados."
)
```

### Adicionar verificação de reputação

```python
from storage.db import insert_reputation_check
import json

insert_reputation_check(
    analysis_id=analysis_id,
    source='GOOGLE_SAFE_BROWSING',
    status='NEGATIVE',  #ou 'POSITIVE'
    raw_json=json.dumps({"status": "ok"}),
    reason='ok',
    elapsed_ms=150
)
```

### Adicionar resultado de heurística

```python
from storage.db import insert_heuristic_hit

insert_heuristic_hit(
    analysis_id=analysis_id,
    heuristic_code='DOMAIN_AGE',  #Código da heurística (deve existir na tabela heuristics)
    severity='MEDIUM',            #'LOW','MEDIUM', 'HIGH', 'CRITICAL'
    triggered=True,               #True se a heurística foi acionada, False caso contrário
    details='Domínio criado há 6 meses'
)
```

### Adicionar requisição de IA

```python
from storage.db import insert_ai_request
import json

insert_ai_request(
    analysis_id=analysis_id,
    model='gpt-4',
    prompt='Analise esta URL...',
    response='A URL apresenta riscos...',
    risk_score=75.5,  #Opcional: score de risco calculado pela IA (0-100)
    meta=json.dumps({"tokens": 150, "temperature": 0.7})  #Opcional: metadados em JSON
)
```

### Buscar análise

```python
from storage.db import get_analysis_by_id, get_analysis_by_url, get_full_analysis

#Buscar análise por ID
analysis = get_analysis_by_id(analysis_id)

#Buscar análise mais recente por URL normalizada
analysis = get_analysis_by_url("https://example.com/path")

#Buscar análise completa (com reputação e heurísticas)
full = get_full_analysis(analysis_id)
```

## Funções Disponíveis

### Inserção
- `insert_analysis()` - Insere uma nova análise (cria link automaticamente se necessário)
- `insert_reputation_check()` - Insere verificação de reputação
- `insert_heuristic_hit()` - Insere resultado de heurística (usa código da heurística)
- `insert_ai_request()` - Insere requisição de IA

### Consulta
- `get_analysis_by_id()` - Busca análise por ID (inclui informações do link)
- `get_analysis_by_url()` - Busca análise mais recente por URL normalizada (inclui informações do link)
- `get_reputation_checks()` - Lista verificações de reputação de uma análise
- `get_heuristics_hits()` - Lista resultados de heurísticas de uma análise (inclui informações da heurística)
- `get_ai_requests()` - Lista requisições de IA de uma análise
- `get_full_analysis()` - Busca análise completa com todas as informações relacionadas (link, reputação, heurísticas e IA)

### Estatísticas
- `get_analyses_stats()` - Retorna estatísticas do banco de dados

## Configuração

O caminho do banco de dados pode ser configurado via variável de ambiente:

```bash
export CLICKSAFE_DB_PATH=/path/to/custom.db
```

Ou modificando diretamente em `db.py`:

```python
DB_PATH = 'meu_banco.db'
```

## Exemplo Completo

Veja `app.py` no diretório `backend/` para um exemplo completo de uso.

## Testar

Execute o exemplo:

``` bash
cd backend
python app.py
```

``` bash
python3 -m uvicorn server:app --host 0.0.0.0 --port 8000 --reload
```
**Nota:** O --reload do Uvicorn reinicia automaticamente o servidor sempre que altera o código.

**Acessar:** http://localhost:8000

**Documentação interativa:** http://localhost:8000/docs

Frontend (rodar em outro terminal):

``` bash
cd frontend
npm run dev
```

**Acessar o frontend:** http://localhost:5173