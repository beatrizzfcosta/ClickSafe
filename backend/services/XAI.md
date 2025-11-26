## Processos necessários para o Funcionamento do Serviço XAI

### 1. Instalar o Ollama 
- Para o serviço funcionar, **é obrigatório instalar o Ollama localmente no computador/servidor** onde o backend é executado.
- Para o **Windows**, é necessário fazer o download do Ollama em https://ollama.com/download

**Código para o MacBook**

```sh
brew install ollama
ollama serve &
```

**Código para o Windows**

```sh
ollama serve 
```

### 2. Instalar o Modelo Mistral no Ollama

**Código para o MacBook e Windows**

```sh
ollama pull mistral
```

### 3. Garantir que o Python Consegue Executar Subprocessos
- O ambiente deve permitir execução de `subprocess.run`.
- O binário `ollama` deve estar no PATH do sistema.

**Verificar execução subprocessos/permissões**

```sh
where ollama
```

```sh
Get-Process ollama
```

### 4. Verificar Permissões no Servidor
- O utilizador que executa o backend deve ter permissão para correr `ollama`.
- Em sistemas Linux, garantir que o serviço não corre num ambiente isolado sem acesso ao binário.

### 5. Configuração do Backend
- O ficheiro `xai.py` deve estar dentro da estrutura `backend/services/`.
- Garantir dependências instaladas:

```sh
pip install -r requirements.txt
```

### 6. Execução
Chamar:
```python
explain_result(url, heuristics, reputation)
```
O serviço faz:
1. Construção do prompt
2. Execução do comando `ollama run mistral`
3. Devolve o output produzido pelo modelo

### 7. Tratamento de Erros
Se o Ollama falhar:
- Verificar logs (**Para MacBook e Windows**):

```sh
ollama serve --verbose
```

- Validar se o modelo existe;
- Confirmar se o processo tem permissões.

### 8. Requisitos Mínimos do Sistema
- Python 3.9+;
- Ollama instalado;
- Modelo Mistral disponível;
- Acesso ao binário pelo backend.

### 9. Execução em Produção
- Garantir que o Ollama está ativo como serviço;
- Proteger chamadas externas ao backend;
- Monitorizar tempos de resposta do modelo.

## Referências

- [Ollama Documentation](https://docs.ollama.com)