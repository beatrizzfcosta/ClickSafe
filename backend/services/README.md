# Serviços de Reputação - ClickSafe

Este módulo contém a implementação dos serviços de verificação de reputação de URLs, incluindo Google Safe Browsing (GSB), VirusTotal e PhishTank.

## Índice

1. [Google Safe Browsing (GSB)](#google-safe-browsing-gsb)
   - [Obter Chave de API](#obter-chave-de-api)
   - [Configuração](#configuração)
   - [Implementação](#implementação)
   - [Uso](#uso)
2. [VirusTotal e PhishTank](#virustotal-e-phishtank)
3. [Estrutura de Arquivos](#estrutura-de-arquivos)

---

## Google Safe Browsing (GSB)

### Obter Chave de API

#### 1. Acessar Google Cloud Console

1. Acessar: https://console.cloud.google.com/
2. Fazer login com conta Google
3. Criar um novo projeto ou selecionar um existente:
   - Clicar em "Select a project" no topo
   - Clicar em "New Project"
   - Digitar o nome (ex: "ClickSafe")
   - Clicar em "Create"

#### 2. Habilitar a API

1. No menu lateral, em **APIs & Services** → **Library**
2. Buscar por "Safe Browsing API"
3. Clicar em "Google Safe Browsing API"
4. Clicar em **Enable**

#### 3. Criar Credencial (API Key)

1. Em **APIs & Services** → **Credentials**
2. Clicar em **+ Create Credentials** → **API Key**
3. Uma chave será gerada automaticamente
4. **Importante**: Clicar em **Restrict Key** para segurança:
   - Em **Application restrictions**: Selecionar "None" (para desenvolvimento) ou "IP addresses" (para produção)
   - Em **API restrictions**: Selecionar "Restrict key" e escolher "Google Safe Browsing API"
   - Clicar em **Save**

#### 4. Copiar a Chave

A chave será exibida no formato: `AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`

**Importante**: Manter esta chave segura e nunca a commite no Git!

---

### Configuração

#### 1. Instalar Dependências

```bash
cd backend
pip install httpx python-dotenv
```

Ou usando o arquivo de requirements:

```bash
pip install -r services/requirements.txt
```

#### 2. Criar Arquivo de Configuração

Criar o arquivo `.env.local` no diretório `backend/`:

```bash
cd backend
echo "GSB_API_KEY=chave_aqui" > .env.local
```

Ou editar manualmente:

```bash
# backend/.env.local
GSB_API_KEY=AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

**Segurança**: O arquivo `.env.local` já está no `.gitignore` e não será commitado.

---

### Implementação

#### Arquivo: `gsb.py`

O módulo `gsb.py` implementa a consulta ao Google Safe Browsing API v4.

**Características principais:**

1. **Carregamento Automático de Variáveis de Ambiente**
   ```python
   # Carrega automaticamente do .env.local
   from dotenv import load_dotenv
   env_path = Path(__file__).parent.parent / '.env.local'
   if env_path.exists():
       load_dotenv(env_path)
   ```

2. **Função Principal: `check_gsb(url: str)`**
   - Consulta assíncrona à API do Google Safe Browsing
   - Retorna formato padronizado:
     ```python
     {
         "status": "POSITIVE" | "NEGATIVE" | "UNKNOWN",
         "reason": "ok" | "no_key" | "timeout" | "error:...",
         "raw": {...},  # Resposta completa da API
         "elapsed_ms": int  # Tempo de resposta em milissegundos
     }
     ```

3. **Tratamento de Erros**
   - `no_key`: Chave de API não configurada
   - `timeout`: Requisição excedeu 3 segundos
   - `http_XXX`: Erro HTTP (ex: `http_403`, `http_429`)
   - `error:ExceptionType`: Outros erros

4. **Tipos de Ameaças Verificadas**
   - `MALWARE`: Software malicioso
   - `SOCIAL_ENGINEERING`: Engenharia social (phishing)
   - `UNWANTED_SOFTWARE`: Software indesejado
   - `POTENTIALLY_HARMFUL_APPLICATION`: Aplicações potencialmente prejudiciais

**Exemplo de Payload:**

```python
{
    "client": {
        "clientId": "clicksafe",
        "clientVersion": "1.0"
    },
    "threatInfo": {
        "threatTypes": [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION"
        ],
        "platformTypes": ["ANY_PLATFORM"],
        "threatEntryTypes": ["URL"],
        "threatEntries": [{"url": "https://example.com"}]
    }
}
```

#### Arquivo: `reputation.py`

Consolida resultados de múltiplas fontes de reputação.

**Função: `consolidate_reputation(url: str)`**

- Chama `check_gsb()` para Google Safe Browsing
- Mantém VirusTotal e PhishTank como stubs (mockados)
- Calcula score agregado (0.0 a 1.0)
- Retorna:
  ```python
  {
      "sources": {
          "GOOGLE_SAFE_BROWSING": {...},
          "VIRUSTOTAL": {"status": "UNKNOWN", "reason": "stub"},
          "PHISHTANK": {"status": "UNKNOWN", "reason": "stub"}
      },
      "_score": 0.3333  # Score agregado (0.0 = seguro, 1.0 = perigoso)
  }
  ```

**Cálculo de Score:**
- `POSITIVE` (risco detectado): 1.0
- `NEGATIVE` (seguro): 0.0
- `UNKNOWN` (indeterminado): 0.5
- Score final = média dos scores de todas as fontes

---

### Uso

#### 1. Teste via CLI

```bash
cd backend
python services/test_gsb_cli.py https://example.com
```

**Saída esperada:**

```json
{
  "sources": {
    "GOOGLE_SAFE_BROWSING": {
      "status": "NEGATIVE",
      "reason": "ok",
      "raw": {},
      "elapsed_ms": 227
    },
    "VIRUSTOTAL": {
      "status": "UNKNOWN",
      "reason": "stub",
      "raw": {}
    },
    "PHISHTANK": {
      "status": "UNKNOWN",
      "reason": "stub",
      "raw": {}
    }
  },
  "_score": 0.3333
}
```

#### 2. Uso no Código

```python
from services.reputation import consolidate_reputation
import asyncio

async def main():
    result = await consolidate_reputation("https://example.com")
    print(result["sources"]["GOOGLE_SAFE_BROWSING"]["status"])
    # Output: NEGATIVE

asyncio.run(main())
```

#### 3. Integração com Banco de Dados

O `app.py` já integra automaticamente:

```python
from app import analyze_url

result = await analyze_url("https://example.com")
# Salva automaticamente no banco de dados
# Retorna análise completa com todas as verificações
```

---

## VirusTotal e PhishTank

Atualmente implementados como **stubs** (mockados), retornando sempre:

```python
{
    "status": "UNKNOWN",
    "reason": "stub",
    "raw": {}
}
```

### Próximos Passos

Para implementar VirusTotal:

1. Obter chave de API em: https://www.virustotal.com/gui/join-us
2. Criar arquivo `vt.py` similar ao `gsb.py`
3. Adicionar `VT_API_KEY` ao `.env.local`
4. Atualizar `reputation.py` para chamar `check_vt()` em vez do stub

Para implementar PhishTank:

1. Obter chave de API em: https://www.phishtank.com/api_register.php
2. Criar arquivo `pt.py` similar ao `gsb.py`
3. Adicionar `PT_API_KEY` ao `.env.local`
4. Atualizar `reputation.py` para chamar `check_pt()` em vez do stub

---

## Dependências

- `httpx>=0.24.0`: Cliente HTTP assíncrono para requisições
- `python-dotenv>=1.0.0`: Carregamento de variáveis de ambiente do `.env.local`

---

## Troubleshooting

### Erro: `ModuleNotFoundError: No module named 'httpx'`

```bash
pip install httpx python-dotenv
```

### Erro: `"reason": "no_key"`

Verifique se:
1. O arquivo `.env.local` existe em `backend/`
2. A chave está no formato: `GSB_API_KEY=sua_chave_aqui`
3. Não há espaços extras ou aspas na chave

### Erro: `"reason": "http_403"`

- Verificar se a API está habilitada no Google Cloud Console
- Verificar se a chave tem permissão para a Safe Browsing API
- Verificar se a chave não está restrita a IPs diferentes

### Erro: `"reason": "timeout"`

- A requisição excedeu 3 segundos
- Verificar conexão com a internet
- A API pode estar temporariamente indisponível

---

## Limites e Cotas

O Google Safe Browsing API tem limites:

- **Free Tier**: ~10,000 requisições por dia
- **Rate Limit**: Variável, mas geralmente ~100 requisições/minuto

---

## Referências

- [Google Safe Browsing API v4 Documentation](https://developers.google.com/safe-browsing/v4)