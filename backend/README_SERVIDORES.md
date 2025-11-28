# Servidores ClickSafe

Este projeto possui dois servidores diferentes para diferentes casos de uso.

## Comparação

| Característica | `server.py` | `server_network.py` |
|----------------|-------------|---------------------|
| **Acesso** | Apenas localhost | Rede local completa |
| **CORS** | Apenas localhost:5173, localhost:3000 | Todas as origens (*) |
| **Endpoints extras** | Básicos | Com consultas e estatísticas |
| **Uso** | Desenvolvimento local | Servidor central na rede |
| **IP** | 127.0.0.1 | IP da rede local (ex: 192.168.1.100) |

## Como Usar

### Servidor Local (`server.py`)

Para desenvolvimento normal, apenas localhost:

```bash
cd backend
python3 -m uvicorn server:app --reload
```

Acesse em: `http://localhost:8000`

### Servidor de Rede (`server_network.py`)

Para tornar seu PC um servidor central acessível na rede:

```bash
cd backend
python3 start_server.py
```

Ou manualmente:

```bash
cd backend
python3 -m uvicorn server_network:app --host 0.0.0.0 --port 8000
```

O servidor mostrará o IP da sua máquina. Outros dispositivos na mesma rede podem acessar em:
- `http://[SEU_IP]:8000`
- `http://[SEU_IP]:8000/docs`
