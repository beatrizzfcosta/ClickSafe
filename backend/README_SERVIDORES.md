# Servidores ClickSafe

Este projeto possui dois servidores diferentes para diferentes casos de uso.

## Comparação

| Característica | `server.py` | `server_network.py` |
|----------------|-------------|---------------------|
| **Acesso** | Apenas localhost | Rede local completa |
| **Serve Frontend** | Não (apenas API) | Sim (frontend buildado) |
| **CORS** | Apenas localhost:5173, localhost:3000 | Todas as origens (*) |
| **Endpoints extras** | Básicos | Com consultas e estatísticas |
| **Uso** | Desenvolvimento local (frontend separado) | Servidor central na rede (tudo junto) |
| **IP** | 127.0.0.1 | IP da rede local (ex: 192.168.1.100) |

## Como Usar

**Importante:** Antes de iniciar qualquer servidor, ative o ambiente virtual:

```bash
cd backend
source venv/bin/activate  # No macOS/Linux
# ou
venv\Scripts\activate     # No Windows
```

### Servidor Local (`server.py`)

Para desenvolvimento normal, apenas localhost. **Este servidor NÃO serve o frontend** - apenas a API REST.

**Use este servidor quando:**
- Você está desenvolvendo e quer rodar o frontend separadamente (ex: `npm run dev` no diretório `frontend/`)
- Você quer apenas testar a API

```bash
cd backend
source venv/bin/activate  # Ativar ambiente virtual
python3 -m uvicorn server:app --reload
```

Acesse a API em: `http://localhost:8000`
- Documentação: `http://localhost:8000/docs`
- Health check: `http://localhost:8000/api/health`

**Nota:** O frontend precisa rodar separadamente (ex: `cd frontend && npm run dev`) e fazer requisições para `http://localhost:8000/api/analyze`

### Servidor de Rede (`server_network.py`)

Para tornar seu PC um servidor central acessível na rede. **Este servidor serve tanto a API quanto o frontend buildado.**

**Use este servidor quando:**
- Você quer servir tudo em um único servidor (API + frontend)
- Você quer que outros dispositivos na rede acessem a aplicação
- Você está em produção ou demonstração

**Importante:** Antes de iniciar, certifique-se de que o frontend foi buildado:
```bash
cd frontend
npm run build
```

Depois, inicie o servidor:

```bash
cd backend
source venv/bin/activate  # Ativar ambiente virtual
python3 start_server.py
```

Ou manualmente:

```bash
cd backend
source venv/bin/activate  # Ativar ambiente virtual
python3 -m uvicorn server_network:app --host 0.0.0.0 --port 8000 --reload
```

**Nota:** O script `start_server.py` detecta automaticamente o ambiente virtual, mas é recomendado ativá-lo manualmente.

O servidor mostrará o IP da sua máquina. Outros dispositivos na mesma rede podem acessar em:
- `http://[SEU_IP]:8000` - Frontend completo
- `http://[SEU_IP]:8000/docs` - Documentação da API
- `http://[SEU_IP]:8000/api/analyze` - Endpoint da API
