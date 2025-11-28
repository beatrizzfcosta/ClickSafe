"""
Script para iniciar o servidor ClickSafe na rede local.
"""
import socket
import sys
import subprocess
import os

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        print(f" Erro ao detectar IP: {e}")
        return "127.0.0.1"


def get_hostname():
    try:
        return socket.gethostname()
    except:
        return "localhost"


def check_port_available(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', port))
            return True
    except OSError:
        return False


def get_python_executable():
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    venv_python = os.path.join(backend_dir, "venv", "bin", "python3")
    
    if os.path.exists(venv_python):
        return venv_python
    
    # Tentar também sem o "3"
    venv_python2 = os.path.join(backend_dir, "venv", "bin", "python")
    if os.path.exists(venv_python2):
        return venv_python2
    
    return sys.executable

def main():
    local_ip = get_local_ip()
    hostname = get_hostname()
    port = 8000
    
    print("=" * 60)
    print("Iniciando ClickSafe Server na Rede Local")
    print("=" * 60)
    print(f"Hostname: {hostname}")
    print(f"IP Local: {local_ip}")
    print(f"Porta: {port}")
    print()
    print("URLs de acesso:")
    print(f"   - Local:     http://localhost:{port}")
    print(f"   - Rede:      http://{local_ip}:{port}")
    print(f"   - Docs:      http://{local_ip}:{port}/docs")
    print()
    print("Outros dispositivos na rede podem acessar:")
    print(f"   http://{local_ip}:{port}")
    print()
    print("Certifique-se de que o firewall permite conexões na porta 8000")
    print("=" * 60)
    print()
    
    if not check_port_available(port):
        print(f"\n AVISO: A porta {port} já está em uso!")
        print(f"\nVerificando processo na porta {port}...")
        try:
            result = subprocess.run(
                ["lsof", "-ti", f":{port}"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0 and result.stdout.strip():
                pids = result.stdout.strip().split('\n')
                print(f"  Processos encontrados: {', '.join(pids)}")
                print(f"\nPara parar automaticamente, execute:")
                print(f"  python3 stop_server.py")
                print(f"\nOu manualmente:")
                for pid in pids:
                    if pid:
                        print(f"  kill {pid}")
            else:
                print(f"  Nenhum processo encontrado (pode ser que a porta ainda esteja sendo liberada)")
                print(f"  Aguarde alguns segundos e tente novamente")
        except FileNotFoundError:
            print(f"  (lsof não disponível - use manualmente: lsof -ti:{port} | xargs kill)")
        except Exception as e:
            print(f"  Erro ao verificar: {e}")
        
        print(f"\nOu use outra porta editando o script (linha 58: port = 8000)")
        sys.exit(1)
    
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(backend_dir)
    python_exe = get_python_executable()
    
    try:
        print("Iniciando servidor uvicorn...")
        print(f"Python: {python_exe}")
        print("(Pressione Ctrl+C para parar)\n")
        subprocess.run([
            python_exe, "-m", "uvicorn",
            "server_network:app",
            "--host", "0.0.0.0",
            "--port", str(port),
            "--reload"
        ], check=True)
    except KeyboardInterrupt:
        print("\n\nServidor encerrado pelo usuário")
    except subprocess.CalledProcessError as e:
        print(f"\nErro ao iniciar servidor: {e}")
        print(f"\nTente executar manualmente:")
        print(f"  cd {backend_dir}")
        print(f"  {python_exe} -m uvicorn server_network:app --host 0.0.0.0 --port {port}")
        sys.exit(1)
    except Exception as e:
        print(f"\nErro inesperado: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()