# Serviços de Reputação - ClickSafe

Este módulo contém a implementação dos serviços de verificação de reputação de URLs, incluindo Google Safe Browsing (GSB), VirusTotal e APIVOID.

## Índice

1. [Google Safe Browsing (GSB)](#google-safe-browsing-gsb)
   - [Obter Chave de API](#obter-chave-de-api)
   - [Configuração do GSB](#configuração)
   - [Implementação](#implementação)
   - [Uso](#uso)

2. [VirusTotal](#virustotal)
   - [Obter Chave de API](#obter-chave-de-api-1)
   - [Limites da API](#limites-da-api)
   - [Configuração do VirusTotal](#configuração-do-virustotal)
   - [Implementação](#implementação-1)

3. [APIVOID](#apivoid)
   - [Obter Chave de API](#obter-chave-de-api-2)
   - [Funcionamento](#funcionamento)
   - [Lógica de Interpretação](#lógica-de-interpretação)
   - [Exemplo de Retorno](#exemplo-de-retorno)

4. [Dependências](#dependências)
5. [Troubleshooting](#troubleshooting)
6. [Limites e Cotas](#limites-e-cotas)
7. [Referências](#referências)


## Google Safe Browsing (GSB)

### Obter Chave de API
1. Acesse o **Google Cloud Console**: https://console.cloud.google.com/
2. Faça login.
3. Crie ou selecione um projeto.
4. Ative a Safe Browsing API:
- **APIs & Services → Library** → "Safe Browsing API" → **Enable**
5. Crie uma API key:
- **APIs & Services → Credentials → Create Credentials → API Key**
6. Restrinja a chave conforme as suas preferências.

**Importante:** Nunca dar commit na chave no Git.

### Configuração

#### 1. Instalar Dependências

**Usando ambiente virtual**

```bash
cd backend/services
python3 -m venv venv
source venv/bin/activate  #No macOS/Linux
#ou: venv\Scripts\activate  #No Windows
pip install -r requirements.txt
```

#### Adicionar chave ao `.env.local` 
Criar o arquivo `.env.local` no diretório `backend/`:
```bash
cd backend
echo "GSB_API_KEY=chave_aqui" > .env.local
```
**Ou editar manualmente:**

```bash
#backend/.env.local
GSB_API_KEY=AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

**Segurança**: O arquivo `.env.local` já está no `.gitignore` e não será commitado.

### Implementação

#### Arquivo: `gsb.py`

O módulo `gsb.py` implementa a consulta ao Google Safe Browsing API v4.

**Características principais:**

1. **Carregamento Automático de Variáveis de Ambiente**
   ```python
   #Carrega automaticamente do .env.local
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
         "raw": {...},  #Resposta completa da API
         "elapsed_ms": int  #Tempo de resposta em milissegundos
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

- Executa `check_gsb()` para Google Safe Browsing
- Mantém VirusTotal e APIVOID como **stubs** (mockados)
- Calcula score agregado (0.0-1.0)
- Retorna:
  ```python
  {
      "sources": {
          "GOOGLE_SAFE_BROWSING": {...},
          "VIRUSTOTAL": {"status": "UNKNOWN", "reason": "stub"},
          "APIVOID": {"status": "UNKNOWN", "reason": "stub"}
      },
      "_score": 0.3333  #Score agregado (0.0 = seguro, 1.0 = perigoso)
  }
  ```

**Cálculo de Score:**
- `POSITIVE` (risco detectado): 1.0
- `NEGATIVE` (seguro): 0.0
- `UNKNOWN` (indeterminado): 0.5
- Score final = média dos scores de todas as fontes

### Uso

#### 1. Teste via CLI

**Com ambiente virtual ativo:**

```bash
cd backend/services
source venv/bin/activate  #Ativar o venv
python gsb/test_gsb_cli.py https://google.com #"malicious":false
python gsb/test_gsb_cli.py http://malware.testing.google.test/testing/malware/ #"malicious":true
```

**Ou usando o Python do venv diretamente:**

```bash
cd backend/services
venv/bin/python gsb/test_gsb_cli.py https://example.com
```

**Sem ambiente virtual:**

```bash
cd backend
python services/gsb/test_gsb_cli.py https://example.com
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
    "APIVOID": {
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
    #Output: NEGATIVE

asyncio.run(main())
```

#### 3. Integração com Banco de Dados

O `app.py` já integra automaticamente:

```python
from app import analyze_url

result = await analyze_url("https://example.com")
#Salva automaticamente no BD e Retorna análise completa
```

## VirusTotal

### Obter Chave de API

1. Criar Conta: https://www.virustotal.com/gui/join-us
2. Acessar perfil e Selecionar **API key** no menu
3. Copiar a chave de API exibida

**Formato da chave**: Uma string longa de caracteres alfanuméricos (ex: `a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0`)

**Importante**: 
- A chave é pessoal e não deve ser compartilhada
- Mantenha esta chave segura e nunca a commite no Git!
- Planos gratuitos têm limites de requisições (geralmente 4 requisições/minuto)

### Configuração do VirusTotal

Editar o arquivo `.env.local` no diretório `backend/`:

```bash
#backend/.env.local
VT_API_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
```
---

### Implementação

O módulo `vt.py` já está implementado e segue o mesmo padrão do GSB:

- Função `check_vt(url)` que retorna formato padronizado
- Carregamento automático da API key do `.env.local`
- Tratamento de erros (rate limit, API key inválida, etc.)
- Integração automática na verificação sequencial

**Uso automático**: Quando o GSB retornar NEGATIVE, o sistema verificará automaticamente no VirusTotal (se a API key estiver configurada).

## APIVOID

O módulo do `apivoidrep.py` está implementando seguindo o mesmo padrão de GSB e VirusTotal:

### Obter Chave de API

1. Obter chave de API em: https://dash.apivoid.com/api-keys/
2. Uso do arquivo `apivoidrep.py` 
3. Adicionar `APIVOID_API_KEY` ao `.env.local`
4. Atualizar `reputation.py` para utilizar `check_apivoid()` como fonte oficial de reputação

### Funcionamento
- Consulta o endpoint **URL Reputation API** do APIVOID
- Retorna dados padronizados nos campos:
- `status`: `POSITIVE`, `NEGATIVE` ou `UNKNOWN`
- `reason`: motivo do estado (ex.: `ok`, `no_key`, `invalid_json`, `timeout`, `error:...`)
- `raw`: resposta completa retornada pela API
- `elapsed_ms`: tempo total da requisição

### Lógica de Interpretação
- `score == 0` → **NEGATIVE** (sem risco)
- `score > 0` → **POSITIVE** (URL listada ou suspeita)
- Erros, resposta inválida ou chave ausente: **UNKNOWN**

### Exemplo de Retorno
```json
{
"status": "NEGATIVE",
"reason": "ok",
"raw": {
"data": {
"report": {
"score": 0,
"details": {"blacklists": {"detections": 0}}
}
}
},
"elapsed_ms": 241
}
```

## Dependências
```text
httpx>=0.24.0
python-dotenv>=1.0.0
requests>=2.31.0
```

## Troubleshooting

### Erro: `ModuleNotFoundError: No module named 'httpx'` ou `módulo 'requests' não encontrado`

**Solução 1: Usar ambiente virtual (recomendado)**

```bash
cd backend/services
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Solução 2: Instalar globalmente**

```bash
pip install httpx python-dotenv requests
```

**Solução 3: Se estiver a usar Python do Homebrew**

O Python do Homebrew requer ambiente virtual. Siga a Solução 1 acima.

**Nota**: Se estiver usando conda, certifique-se de que o ambiente está ativado ou use o Python do Homebrew com venv.

### Erro: `"reason": "no_key"`

Verifique se:
1. O arquivo `.env.local` existe em `backend/`
2. As chaves estão no formato: `API_KEY=chave_aqui`
3. Não há espaços extras ou aspas na chave

### Erro: `"reason": "http_403"`

- Verificar se a API está habilitada no Google Cloud Console
- Verificar se a chave tem permissão para as APIs
- Verificar se as chaves não estão restritas a IPs diferentes

### Erro: `"reason": "timeout"`

- A requisição excedeu 3 segundos
- Verificar conexão com a internet
- A API pode estar temporariamente indisponível

## Limites e Cotas

O Google Safe Browsing API tem limites:

- **Free Tier**: ~10,000 requisições por dia;
- **Rate Limit**: Variável, mas geralmente ~100 requisições/minuto.

O VirusTotal tem os seguinte limites:
- **Free Tier**: 4 requisições por minuto
- **Rate Limit**: 4 req/min (pode variar)
- Para uso comercial ou maior volume, considerar planos pagos

Limites do APIVOID:
- Aproximadamente 60 requisições por minuto.

## Referências

- [Google Safe Browsing API v4 Documentation](https://developers.google.com/safe-browsing/v4)
- [VirusTotal Documentation](https://docs.virustotal.com) 
- [APIVOID API V2 Documentation](https://docs.apivoid.com)