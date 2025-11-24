#imports necessários
from datetime import datetime
import re #para poder ver datas
import whois  #para consulta de informações de domínio
import tldextract  #para extrair partes do domínio
import dns.resolver #para verificar registros DNS
import ssl  #para verificar certificados SSL
import urllib.parse  #para analisar URLs
import requests  #para fazer requisições HTTP
import ipaddress  #para verificar endereços IP
from difflib import SequenceMatcher  #para comparar similaridade de strings - typosquatting
import base64  #para verificar codificação base64


#receber o url e extraior dominio, caminho, parametros
def extract_url_components(url):
    parsed_url = urllib.parse.urlparse(url) #analisa a URL
    dominio = parsed_url.netloc #extrai o dominio
    caminho = parsed_url.path #extrai o caminho
    parametros = parsed_url.query #extrai os parametros

    return dominio, caminho, parametros

#pequeno teste
#print (extract_url_components("https://www.google.com/search?client=opera-gx&q=vscode+collaborative+coding&sourceid=opera&ie=UTF-8&oe=UTF-8"))
#resposta --> ('www.google.com', '/search', 'client=opera-gx&q=vscode+collaborative+coding&sourceid=opera&ie=UTF-8&oe=UTF-8')


#-----------------------------------------------Analise do dominio---------------------------------------------------------


# ---idade do dominio - verificar se é muito recente ---

#considerámos que dominios com menos de 30 dias são muto recentes
def check_domain_age_recent(dominio):
    try:
        #consulta as informações do domínio usando a biblioteca whois
        info_dominio = whois.whois(dominio)

        #datas de criação
        data_criacao = info_dominio.creation_date
        
        #cria a data no formato correto se for lista
        if isinstance(data_criacao, list):
            data_criacao = data_criacao[0]

        #verifica a idade do dominio
        if data_criacao:
            dias_de_idade = (datetime.now().date() - data_criacao.date()).days
            return dias_de_idade < 30  #retorna True se o dominio for muito recente
    
    #em caso de erro na consulta whois, retorna None
    except Exception as e:
        print(f"Erro ao verificar idade do domínio: {e}")
        return None


# --- idade do dominio - verificar se esta prestes a expirar ---

#considerámos que dominios com menos de 30 dias para expirar são suspeitos    
def check_domain_age_expiring(dominio):
    try:
        #consulta as informações do domínio usando a biblioteca whois
        info_dominio = whois.whois(dominio)

        #data expiração
        data_expiracao = info_dominio.expiration_date
        #cria as datas no formato correto se forem listas
        if isinstance(data_expiracao, list):
            data_expiracao = data_expiracao[0]


        
        #verifica se o dominio esta prestes a expirar
        if data_expiracao:
            dias_para_expirar = (data_expiracao.date() - datetime.now().date()).days
            
            return dias_para_expirar < 30  #dominio prestes a expirar
        return False  #dominio normal
    #em caso de erro na consulta whois, retorna None
    except Exception as e:
        print(f"Erro ao verificar idade do domínio: {e}")
        return None
    
#pequeno teste
#dominio, caminho, parametros = extract_url_components("https://www.google.com/search?client=opera-gx&q=vscode+collaborative+coding&sourceid=opera&ie=UTF-8&oe=UTF-8")
#respostas:
#print(check_domain_age_recent(dominio)) --> False
#print(check_domain_age_expiring(dominio))--> False
#print (check_domain_age_expiring("zlnewb.bond"))--> False
#print (check_domain_age_recent("zlnewb.bond"))--> True



# --- dominios de nivel superior (TLD) suspeitos (.tk, .ml, .ga, .cf, .gq) ---

#definimos uma lista com os dominios suspeitos 
TLD_SUSPEITOS = {"tk", "ml", "ga", "cf", "gq", "zip", "xyz", "top", "loan", "click", "info", "biz", "date", "win", "party", "link", "club", "me"}

def check_suspicious_tld(dominio):
    #extrai o TLD usando biblioteca tldextract
    tld = tldextract.extract(dominio).suffix

    #retorna True se o TLD for suspeito - se estiver na lista
    return tld in TLD_SUSPEITOS  #retorna True se o TLD for suspeito - se estiver na lista

#pequeno teste
#dominio, caminho, parametros = extract_url_components("https://www.google.com/search?client=opera-gx&q=vscode+collaborative+coding&sourceid=opera&ie=UTF-8&oe=UTF-8")
#respostas:
#print(check_suspicious_tld(dominio)) #--> False
#print (check_suspicious_tld("zlnewb.top")) #--> True



# --- Utiliza endereco IP em vez de nome de dominio ---

def check_ip_instead_of_domain(dominio):
    #extrai o nome do dominio
    nome_dominio = tldextract.extract(dominio).domain
    #verifica se o dominio é um endereco IP
    try:
        ipaddress.ip_address(nome_dominio)
        return True   # é um IP (IPv4 ou IPv6)
    except ValueError:
        return False  #nao é um endereco IP

#pequeno teste
#dominio, caminho, parametros = extract_url_components("https://www.google.com/search?client=opera-gx&q=vscode+collaborative+coding&sourceid=opera&ie=UTF-8&oe=UTF-8")
#respostas:
#print(check_ip_instead_of_domain(dominio)) #--> False
#dominio, caminho, parametros = extract_url_components("http://192.168.1.10/login")
#print (check_ip_instead_of_domain(dominio)) #--> True



# --- Similaridade com dominios conhecidos (typosquatting) ---

#lista de dominios conhecidos para comparar 
# A heurística de ‘similaridade com domínios legítimos’ não tenta cobrir todos os domínios existentes, o que seria impraticável. 
# Em vez disso, o sistema mantém uma lista limitada de domínios de alto valor (grandes marcas)
DOMINIOS_CONHECIDOS = [
    # Motores de busca / tech
    "google.com",
    "microsoft.com",
    "apple.com",

    # Email / contas
    "gmail.com",
    "outlook.com",
    "live.com",
    "hotmail.com",
    "icloud.com",
    "yahoo.com",

    # Redes sociais / comunicação
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "twitter.com",
    "x.com",
    "tiktok.com",
    "linkedin.com",

    # Pagamentos / dinheiro
    "paypal.com",
    "stripe.com",
    "revolut.com",
    "wise.com",
    "millenniumbcp.pt",
    "millennium.pt",
    "cgd.pt",
    "activobank.pt",
    "novobanco.pt",
    "montepio.pt",
    "bancomontepio.pt",
    "santander.pt",
    "moey.pt",
    "creditoagricola.pt",
    "bancobpi.pt",

    # Compras / serviços online
    "amazon.com",
    "ebay.com",
    "aliexpress.com",
    "netflix.com",
    "spotify.com",
    "discord.com",
    "dropbox.com",
]

#calcula e devolve a similaridade entre duas strings - 0 significa nenhuma similaridade, 1 significa iguais
def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()

def check_similar_known_domains(dominio):
    #extrai o dominio base (dominio + sufixo)
    ext = tldextract.extract(dominio)
    dominio_base = f"{ext.domain}.{ext.suffix}"  # "google.com"
    
    #verifica a similaridade com cada dominio conhecido
    for conhecido in DOMINIOS_CONHECIDOS:
        #se a similaridade for maior ou igual a 0.7 (70%) mas menor que 1 (iguais) consideramos suspeito
        if similar(dominio_base, conhecido) >= 0.7 and similar(dominio_base, conhecido) < 1.0:
            #print para teste - pode ser removido depois  
            print (f"Dominio suspeito: {dominio_base} é similar a {conhecido} com similaridade {similar(dominio_base, conhecido)}")
            return True  #dominio suspeito
        
    return False  #dominio normal

#pequeno teste
#dominio, caminho, parametros = extract_url_components("https://www.google.com/search?client=opera-gx&q=vscode+collaborative+coding&sourceid=opera&ie=UTF-8&oe=UTF-8")
#respostas:
#print(check_similar_known_domains(dominio)) #--> False
#print (check_similar_known_domains("www.g00glE.com")) #--> True
#print (check_similar_known_domains("www.arnazon.com")) #--> True



# --- multiplos subniveis de dominio ---
#verifica se ha muitos subniveis (mais de 3) ou hifens no dominio - Se sim, pode ser suspeito
def check_subdomains_sublevels(dominio):
    #extrai o subdominio
    subdomain = tldextract.extract(dominio).subdomain
    #conta os subniveis (pontos no subdominio)
    niveis = subdomain.count('.')
    return niveis >= 3  #retorna True se houver mais de 3 subniveis

# uso de hifens no dominio
def check_domain_hyphens(dominio):
    #extrai o subdominio
    nome_dominio = tldextract.extract(dominio).domain

    #verifica se ha hifens no dominio
    return '-' in nome_dominio

#pequeno teste
#dominio, caminho, parametros = extract_url_components("https://sub1.sub2.sub3.sub4.google.com/search?client=opera-gx&q=vscode+collaborative+coding&sourceid=opera&ie=UTF-8&oe=UTF-8")
#respostas: 
#print(check_subdomains_sublevels(dominio)) #--> True
#print(check_domain_hyphens(dominio)) #--> False
#print (check_subdomains_sublevels("sub1-sub2-sub3-sub4-google.com")) #--> False
#print (check_domain_hyphens("sub1-sub2-sub3-sub4-google.com")) #--> True



# --- ausencia de HTTPS ou certificado SSL invalido -> nao seguro ---

#verifica se a URL usa HTTPS 
def usa_https(url):
    return url.startswith("https://")


#pequeno teste
#print(usa_https("https://google.com"))   # -->True
#print(usa_https("http://google.com"))    # -->False

#verifica se o certificado SSL é valido
def certificado_ssl_ok(url):
    try:
        resposta = requests.get(url, timeout=5)
        # se chegou aqui sem erro de SSL, consideramos OK
        return True
    except requests.exceptions.SSLError as e:
        print("Erro de SSL:", e)
        return False
    except requests.exceptions.RequestException as e:
        # outros erros (timeout, DNS, etc.) não dizem necessariamente que o certificado é mau
        print("Erro ao aceder ao site:", e)
        return None  # None = não foi possível concluir

#pequeno teste
#print(certificado_ssl_ok("https://google.com"))   # --> True
#print(certificado_ssl_ok("https://expired.badssl.com"))  # -->False + erro de SSL



# --- ausencia de registos DNS ---
def check_dns_records(dominio):
    try:
        #tenta resolver o dominio
        dns.resolver.resolve(dominio, 'A')  #registo A (IPv4)
        return True  #registos DNS encontrados
    except dns.resolver.NoAnswer:
        return False  #nenhum registo encontrado
    except dns.resolver.NXDOMAIN:
        return False  #dominio nao existe
    except Exception as e:
        print(f"Erro ao verificar registos DNS: {e}")
        return None  #erro desconhecido

#pequeno teste
#dominio, caminho, parametros = extract_url_components("https://www.google.com/search?client=opera-gx&q=vscode+collaborative+coding&sourceid=opera&ie=UTF-8&oe=UTF-8")
#respostas:
#print(check_dns_records(dominio)) #--> True
#print (check_dns_records("dominiodesconhecidoexemplo12345.com")) #--> False



# --- localização suspeita do servidor (pais de alto risco ou diferente do esperado) ---

#obter o endereco IP do dominio
def obter_ip(dominio):
    try:
        resposta = dns.resolver.resolve(dominio, "A")
        for rdata in resposta:
            return rdata.address  # ex: "142.250.184.78"
    #retorna None em caso de erro - ou nao encontrado
    except Exception as e:
        print("Erro ao resolver IP do domínio:", e)
        return None

#usa ip lookup para geolocalizar o endereco IP
def geolocalizar_ip(ip):
    try:
        #usa o servico ip-api.com para obter informacoes de localizacao
        url = f"http://ip-api.com/json/{ip}"
        resp = requests.get(url, timeout=5)
        dados = resp.json()

        #se nao for sucesso, retorna None
        if dados.get("status") != "success":
            return None

        #retorna um dicionario com pais, regiao, cidade, isp
        return {
            "pais": dados.get("country"),
            "regiao": dados.get("regionName"),
            "cidade": dados.get("city"),
            "isp": dados.get("isp"),
        }
    #retorna None em caso de erro
    except Exception as e:
        print("Erro ao localizar IP:", e)
        return None

PAIS_ESPERADO_POR_TLD = {
    # Europa
    "pt": "Portugal",
    "es": "Spain",
    "fr": "France",
    "de": "Germany",
    "it": "Italy",
    "nl": "Netherlands",
    "be": "Belgium",
    "lu": "Luxembourg",
    "ch": "Switzerland",
    "at": "Austria",
    "uk": "United Kingdom",  # usado em muitos dominios antigos
    "gb": "United Kingdom",
    "ie": "Ireland",
    "se": "Sweden",
    "no": "Norway",
    "dk": "Denmark",
    "fi": "Finland",
    "pl": "Poland",
    "cz": "Czech Republic",
    "sk": "Slovakia",
    "hu": "Hungary",
    "ro": "Romania",
    "bg": "Bulgaria",
    "gr": "Greece",
    "ru": "Russia",

    # América
    "us": "United States",
    "ca": "Canada",
    "mx": "Mexico",
    "br": "Brazil",
    "ar": "Argentina",
    "cl": "Chile",
    "co": "Colombia",
    "pe": "Peru",
    "uy": "Uruguay",
    "ve": "Venezuela",

    # Ásia / Oceânia
    "cn": "China",
    "jp": "Japan",
    "kr": "South Korea",
    "in": "India",
    "hk": "Hong Kong",
    "sg": "Singapore",
    "au": "Australia",
    "nz": "New Zealand",

    # África
    "za": "South Africa",
    "ng": "Nigeria", 
    "eg": "Egypt",
    "ma": "Morocco",
}

PAISES_SUSPEITOS = {
    "Russia",
    "China",
    "North Korea",
    "Iran",
    "Syria",
    "Cuba",
    "Venezuela",
    "Pakistan",
    "Afghanistan",
    "Iraq",
    "Sudan",
    "Libya",
    "Zimbabwe",
    "Myanmar",
    "Bangladesh",
    "Nigeria",
    "Egypt",
    "Turkey",
}

def check_suspicious_server_location(dominio):
    #obter o endereco IP do dominio
    ip = obter_ip(dominio)
    if not ip:
        print("Nao foi possivel obter o IP do dominio.")
        return None  #nao foi possivel obter o IP

    #geolocalizar o IP
    info_localizacao = geolocalizar_ip(ip)
    if not info_localizacao:
        print("Nao foi possivel localizar o IP")
        return None  #nao foi possivel localizar o IP

    pais_servidor = info_localizacao.get("pais")
    if not pais_servidor:
        print("Pais do servidor nao encontrado.")
        return None  #pais nao encontrado

    #extrai o TLD do dominio
    tld = tldextract.extract(dominio).suffix.split('.')[-1]  #pega o ultimo nivel do TLD

    #verifica se ha um pais esperado para esse TLD
    pais_esperado = PAIS_ESPERADO_POR_TLD.get(tld)
    
    #veridica se o pais do servidor é suspeito
    if pais_servidor in PAISES_SUSPEITOS:
        print (f"Pais do servidor suspeito: {pais_servidor}")
        #pais do servidor é suspeito
        return True
    
    #verifica se o pais do servidor é diferente do esperado
    if pais_esperado:
        print (f"Pais do servidor: {pais_servidor}, Pais esperado para TLD .{tld}: {pais_esperado}")
        #compara o pais do servidor com o pais esperado
        return pais_servidor != pais_esperado  #retorna True se for diferente (suspeito)
    print("Pais esperado para o TLD nao encontrado.")
    return False  #sem informacao suficiente para determinar suspeita

#pequeno teste
#dominio, caminho, parametros = extract_url_components("https://www.google.com/search?client=opera-gx&q=vscode+collaborative+coding&sourceid=opera&ie=UTF-8&oe=UTF-8")
#respostas:
#print(check_suspicious_server_location(dominio)) #--> False
#print(check_suspicious_server_location("www.google.fr")) #--> True ou False dependendo da localização do servidor



#-------------------Analise do caminho --------------------

# --- uso de muitos subdiretorios ou caminhos longos ---
#assumimos que mais de 5 subdiretorios é suspeito
def check_long_path(caminho):
    #conta o numero de subdiretorios (partes entre barras)
    subdirs = caminho.split('/')
    return len(subdirs) > 5  #retorna True se houver mais de 5 subdiretorios

#pequenos testes
#dominio, caminho, parametros = extract_url_components("https://www.google.com/a/b/c/d/e/f/g/h")
#print(check_long_path(caminho)) #--> True

#dominio, caminho, parametros = extract_url_components("https://www.google.com/a/b/c")
#print(check_long_path(caminho)) #--> False


# --- subdiretorios administrativos (ex: /admin/, /secure/) - nao devem estar acessiveis publicamente ---
ADMIN_PATH_KEYWORDS = {
    "/admin",
    "/administrator",
    "/admin/login",
    "/admin_panel",
    "/backend",
    "/backoffice",
    "/manage",
    "/management",
    "/dashboard",
    "/controlpanel",
    "/cpanel",
    "/login",
    "/user/login",
    "/auth",
    "/signin",
    "/secure/login",
    "/wp-admin",
    "/wp-login.php",
    "/wp-admin/admin.php",
    "/cms",
    "/cms/admin",
    "/admin.php",
    "/phpmyadmin",
    "/pma",
    "/mysqladmin",
    "/sqladmin",
    "/dbadmin",
    "/server-status",
    "/server-info",
    "/config",
    "/configs",
    "/configuration",
    "/settings",
    "/setup",
    "/install",
    "/installer",
    "/update",
    "/upgrade",
    "/secret",
    "/hidden",
}

def check_admin_paths(caminho):
    sitios = caminho.split('/')  #remove parametros se existirem

    #verifica se algum dos termos administrativos está presente no caminho
    for termo in sitios:
        if str("/")+termo in ADMIN_PATH_KEYWORDS:
            return True  #caminho suspeito
    return False  #caminho normal

#pequenos testes
#dominio, caminho, parametros = extract_url_components("https://www.example.com/admin/login")
#print(check_admin_paths(caminho)) #--> True
#dominio, caminho, parametros = extract_url_components("https://www.example.com/user/profile/configure")
#print(check_admin_paths(caminho)) #--> False


# ---nomes de ficheiros falsos ou apelativos---
SUSPICIOUS_FILE_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "update",
    "confirm",
    "confirmation",
    "password",
    "pass",
    "account",
    "secure",
    "security",
    "bank",
    "billing",
}

SUSPICIOUS_FILE_EXTENSIONS = {
    "php",
    "html",
    "htm",
    "asp",
    "aspx",
    "jsp",
}

def check_suspicious_filenames(caminho):
    #extrai o nome do ficheiro (ultima parte do caminho)
    partes = caminho.split('/')
    nome_ficheiro = partes[-1]  #ultima parte do caminho

    #verifica se o nome do ficheiro contem termos suspeitos
    if nome_ficheiro.split('.')[0] in SUSPICIOUS_FILE_KEYWORDS and  nome_ficheiro.split('.')[1] in SUSPICIOUS_FILE_EXTENSIONS:
        return True  #nome de ficheiro suspeito
    return False  #nome de ficheiro normal

#pequenos testes
#dominio, caminho, parametros = extract_url_components("https://www.example.com/verify.php")
#print(check_suspicious_filenames(caminho)) #--> True
#dominio, caminho, parametros = extract_url_components("https://www.example.com/images/photo.jpg")
#print(check_suspicious_filenames(caminho)) #--> False


# --- executaveis disfarcadas (ex: .exe) ---
EXECUTABLE_EXTS = {
    ".exe", ".bat", ".cmd", ".scr",
    ".js", ".jse", ".vbs", ".vbe",
    ".ps1", ".psm1",
    ".jar", ".com", ".msi",
}

def check_executable_extensions(caminho):
    partes = caminho.split('/')
    extensoes = partes[-1].split('.')  #ultima parte do caminho (nome do ficheiro)

    if (str(".")+extensoes[-1]) in EXECUTABLE_EXTS:
        return True  #extensao de executavel encontrada
    else:
        return False  #sem extensao dupla
    
#pequenos testes
#dominio, caminho, parametros = extract_url_components("https://www.example.com/image.bat")
#print(check_executable_extensions(caminho)) #--> True
#dominio, caminho, parametros = extract_url_components("https://www.example.com/document.pdf")
#print(check_executable_extensions(caminho)) #--> False


# --- termos de engenharia social no caminho ---
SOCIAL_ENGINEERING_KEYWORDS = {
    "free",
    "offer",
    "click",
    "here",
    "urgent",
    "limited",
    "winner",
    "prize",
    "reward",
    "bonus",
    "cash",
    "money",
    "deal",
    "save",
    "now",
    "subscribe",
    "buy",
    "purchase",
    "discount",
    "booking",  # Termos relacionados a reservas falsas (phishing de hotéis/viagens)
    "reservation",
    "confirm",
    "verify",
    "update",
}
def check_social_engineering_path(caminho):

    partes = caminho.split('/')
    caminho_lower = caminho.lower()

    #verifica se algum dos termos de engenharia social está presente no caminho
    # Primeiro verifica se o termo está como parte separada
    for termo in partes:
        if termo.lower() in SOCIAL_ENGINEERING_KEYWORDS:
            return True  #caminho suspeito
    
    # Depois verifica se algum termo está contido dentro de outras palavras
    # (ex: "booking" em "FranciscaBooking_FN")
    for termo in SOCIAL_ENGINEERING_KEYWORDS:
        if termo in caminho_lower:
            return True  #termo suspeito encontrado no caminho
    
    return False  #caminho normal   

#pequenos testes
#dominio, caminho, parametros = extract_url_components("https://www.example.com/free/prize/winner")
#print(check_social_engineering_path(caminho)) #--> True
#dominio, caminho, parametros = extract_url_components("https://www.example.com/user/profile")
#print(check_social_engineering_path(caminho)) #--> False


#-------------------Analise dos parametros --------------------

# --- uso excessivo de parametros na URL - numero excessivo ---
#assumimos que mais de 5 parametros é suspeito
def check_excessive_parameters(parametros):
    #divide os parametros pelo '&' e conta
    params_list = parametros.split('&')
    return len(params_list) > 5  #retorna True se for suspeito

#pequeno teste
#dominio, caminho, parametros = extract_url_components("https://www.google.com/search?client=opera-gx&q=vscode+collaborative+coding&sourceid=opera&ie=UTF-8&oe=UTF-8&param1=val1&param2=val2&param3=val3")
#print(check_excessive_parameters(parametros)) #--> True
#dominio, caminho, parametros = extract_url_components("https://www.google.com/search?client=opera-gx&q=vscode+collaborative+coding")
#print(check_excessive_parameters(parametros)) #--> False


#variaveis sensiveis (ex token, auth, sessionid) na URL
SENSITIVE_PARAM_NAMES = {
    "password", "pass", "pwd",
    "token", "auth", "session",
    "creditcard", "cc", "card", "pin",
}

def check_sensitive_parameters(parametros):
    #divide os parametros pelo '&'
    params_list = parametros.split('&')

    #verifica se algum dos parametros é sensivel
    for param in params_list:
        nome_param = param.split('=')[0].lower()  #nome do parametro
        if nome_param in SENSITIVE_PARAM_NAMES:
            return True  #parametro sensivel encontrado
    return False  #nenhum parametro sensivel encontrado

#pequeno teste
#dominio, caminho, parametros = extract_url_components("https://www.example.com/page?token=abc123&user=teste")
#print(check_sensitive_parameters(parametros)) #--> True
#dominio, caminho, parametros = extract_url_components("https://www.example.com/page?user=teste&id=456")
#print(check_sensitive_parameters(parametros)) #--> False


# --- valores demasiado longos ou codificados ---
#asumimos que valores com mais de 100 caracteres ou que parecem codificados em base64 são suspeitos
def check_long_encoded_parameters(parametros):
    # Se não há parâmetros, retorna False
    if not parametros or not parametros.strip():
        return False
    
    #divide os parametros pelo '&'
    params_list = parametros.split('&')

    for param in params_list:
        # Verifica se o parâmetro tem '=' (tem valor)
        if '=' not in param:
            continue
        
        partes = param.split('=', 1)  # Divide apenas no primeiro '='
        if len(partes) < 2:
            continue
            
        valor_param = partes[1]

        #verifica se o valor é demasiado longo (mais de 100 caracteres)
        if len(valor_param) > 100:
            return True  #parametro com valor demasiado longo encontrado
        
        #verifica se o valor parece estar codificado em base64 (caracteres comuns)
        try:
            if len(valor_param) % 4 == 0 and base64.b64decode(valor_param, validate=True):
                return True  #parametro com valor possivelmente codificado encontrado
        except Exception:
            # Se não conseguir decodificar, não é base64 válido
            pass
    return False  #nenhum parametro suspeito encontrado

#pequeno teste
#dominio, caminho, parametros = extract_url_components("https://www.example.com/page?data=VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIHdpdGggbW9yZSB0aGFuIDEwMCBjaGFyYWN0ZXJzIGFuZCBzb21lIG1vcmUgdGV4dCB0byBzZWUgaWYgdGhpcyB3b3Jrcw==")
#print(check_long_encoded_parameters(parametros)) #--> True
#dominio, caminho, parametros = extract_url_components("https://www.example.com/page?info=shortvalue")
#print(check_long_encoded_parameters(parametros)) #--> False


# --- parametros de redirecionamento ---
REDIRECT_PARAM_NAMES = {"redirect", "url", "next", "dest", "destination", "goto"}
def check_redirect_parameters(parametros):
    #divide os parametros pelo '&'
    params_list = parametros.split('&')

    #verifica se algum dos parametros é de redirecionamento
    for param in params_list:
        nome_param = param.split('=')[0].lower()  #nome do parametro
        if nome_param in REDIRECT_PARAM_NAMES:
            return True  #parametro de redirecionamento encontrado
    return False  #nenhum parametro de redirecionamento encontrado

#pequeno teste
#dominio, caminho, parametros = extract_url_components("https://www.example.com/page?redirect=https%3A%2F%2Fevil.com")
#print(check_redirect_parameters(parametros)) #--> True
#dominio, caminho, parametros = extract_url_components("https://www.example.com/page?user=teste")
#print(check_redirect_parameters(parametros)) #--> False


# --- inclusao de dados pessoais (ex: nome, email) na URL ---
PERSONAL_DATA_PARAM_NAMES = {
    "name", "fullname", "first_name", "last_name",
    "email", "e-mail", "phone", "tel", "address",
}
def check_personal_data_parameters(parametros):
    #divide os parametros pelo '&'
    params_list = parametros.split('&')

    #verifica se algum dos parametros é de dados pessoais
    for param in params_list:
        nome_param = param.split('=')[0].lower()  #nome do parametro
        if nome_param in PERSONAL_DATA_PARAM_NAMES:
            return True  #parametro de dados pessoais encontrado
    return False  #nenhum parametro de dados pessoais encontrado

#pequeno teste
#dominio, caminho, parametros = extract_url_components("https://www.example.com/page?email=user%40example.com&name=John")
#print(check_personal_data_parameters(parametros)) #--> True
#dominio, caminho, parametros = extract_url_components("https://www.example.com/page?id=123")
#print(check_personal_data_parameters(parametros)) #--> False


#-------------------Analise encurtadores e redirecionamentos --------------------

# --- uso de servicos de encurtamento de URL (bit.ly, tinyurl) - pode ocultar o destino real ---
URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "t.co",
    "t.me",  # Telegram - pode ser usado para ocultar URLs
    "is.gd",
    "buff.ly",
    "adf.ly",
    "bit.do",
    "cutt.ly",
    "shorte.st",
}

def check_url_shortener(dominio):
    #extrai o dominio base (dominio + sufixo)
    ext = tldextract.extract(dominio)
    dominio_base = f"{ext.domain}.{ext.suffix}"  # por exemplo "bit.ly"

    return dominio_base in URL_SHORTENERS  #retorna True se for um encurtador conhecido

#pequeno teste
#dominio, caminho, parametros = extract_url_components("https://bit.ly/example")
#print(check_url_shortener(dominio)) #--> True
#dominio, caminho, parametros = extract_url_components("https://www.google.com/search?client=opera-gx&q=vscode+collaborative+coding&sourceid=opera&ie=UTF-8&oe=UTF-8")
#print(check_url_shortener(dominio)) #--> False


# --- redirecionamentos multiplos ou cadeias de redirecionamento ---


#TODO reverrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr



def check_multiple_redirects(url):
    try:
        resposta = requests.get(url, timeout=5)
        #verifica o numero de redirecionamentos
        num_redirects = len(resposta.history)
        return num_redirects > 3  #retorna True se houver mais de 3 redirecionamentos
    except Exception as e:
        print(f"Erro ao verificar redirecionamentos: {e}")
        return False  # tratamos de erros como "não foi detetada cadeia longa"
    
#pequeno teste
#print(check_multiple_redirects("https://httpbin.org/redirect/6")) #--> False
#print(check_multiple_redirects("https://www.google.com")) #--> False



# --- urls com protocolos embutidos ---
def check_embedded_protocols(url):
    #verifica se ha protocolos embutidos na URL
    protocolos = ["http://", "https://", "ftp://", "ftps://"]
    count = 0
    for protocolo in protocolos:
        count += url.count(protocolo)
    return count > 1  #retorna True se houver mais de 1 protocolo

#pequenos testes

#print(check_embedded_protocols("http://example.com/http://example.com")) #--> True
#print(check_embedded_protocols("https://example.com/page")) #--> False



#-------------------Padroes de engenharia social --------------------

#--- mistura de idiomas---
#para simplificacao, esta funcao ira apenas verificar se ha ingles e portugues na URL

#palavras comuns portuguesas
COMMON_PORTUGUESE_WORDS = {
    "bem-vindo", "conta", "senha", "segurança", "atualizar", "verificar", "clique", "aqui", "urgente", "oferta", "gratis", "premio", "dinheiro", "bonus",
    "banco", "fatura", "factura", "pagamento", "seguro", "segura", "autenticacao", "confirmar", "actualizar", "atualizar",
    "acesso", "dados", "cliente", "utilizador", "senha",
}

#palavras comuns inglesas
COMMON_ENGLISH_WORDS = {
    "welcome", "account", "password", "security", "update", "verify", "click", "here", "urgent", "offer", "free", "prize", "money", "bonus",
    "bank", "billing", "payment", "secure", "authentication", "confirm",
    "access", "data", "user", "username", 
}

def check_mixed_languages(url):
    url_lower = url.lower()

    #verifica se ha alguma palavra em portugues e/ou em ingles
    found_portuguese = any(word in url_lower for word in COMMON_PORTUGUESE_WORDS)
    found_english = any(word in url_lower for word in COMMON_ENGLISH_WORDS)

    #verifica se ha palavras em pt e em
    if found_portuguese and found_english:
        return True  #mistura de idiomas encontrada

    #verifica se ha caracteres especiais de outros idiomas
    #for char in url:
    #    if ord(char) > 127:
    #        return True  #caracter especial encontrado

    return False  #sem mistura de idiomas ou caracteres especiais

#pequenos testes
#print(check_mixed_languages("https://example.com/welcome/bem-vindo")) #--> True
#print(check_mixed_languages("https://example.com/conta/secure")) #--> True
#print(check_mixed_languages("https://example.com/page")) #--> False
    


#uso de simbolos ou emojis na URL
#vamos verificar se link tem caracteres que nao sao ASCII
def check_symbols_emojis(url):
    for char in url:
        #caracteres nao ascii estao fora do intervalo 0-127
        if ord(char) > 127:  
            return True
    return False  

#pequenos testes
#print(check_symbols_emojis("https://example.com/😊")) #--> True
#print (check_symbols_emojis("https://exámple.com/page")) #--> True
#print(check_symbols_emojis("https://example.com/page?")) #--> False



#frases apelativas ou urgentes 

APPEALING_PHRASES_ENGLISH = {
    "act-now",
    "limited-time",
    "don't-miss",
    "click-here",
    "exclusive-offer",
    "winner",
    "congratulations",
    "you've-won",
    "claim-your-prize",
    "urgent-action-required",
}

FRASES_APELATIVAS_PORTUGUES = {
    "tempo-limitado",
    "nao-perca",
    "clique-aqui",
    "oferta-exclusiva",
    "vencedor",
    "parabens",
    "voce-ganhou",
    "reclame-seu-premio",
    "acao-urgente-necessaria",
}

def check_appealing_phrases(url):
    url_lower = url.lower()

    for phrase in APPEALING_PHRASES_ENGLISH:
        if phrase in url_lower:
            #frase apelativa encontrada
            return True 
    
    for frase in FRASES_APELATIVAS_PORTUGUES:
        if frase in url_lower:
            #frase apelativa encontrada
            return True  
    
    #nao encontrou frases apelativas
    return False  

#pequenos testes
#print(check_appealing_phrases("https://example.com/act-now")) #--> True
#print(check_appealing_phrases("https://example.com/parabens")) #--> True
#print(check_appealing_phrases("https://example.com/page")) #--> False

#repeticao de palavras 
def check_repeated_words(url):
    url_lower = url.lower()

    # separar todas as palavras do URL
    parts = re.split(r"[-_/?.=&%:]+", url_lower)
    # tirar strings vazias
    parts_finais = []
    for item in parts:
        if item != "":
            parts_finais.append(item)

    word_counts = {}
    for word in parts_finais:
        if word in word_counts:
            word_counts[word] += 1
            #se a palavra ja apareceu mais de 2 vezes, consideramos suspeito
            if word_counts[word] > 2:
                return True
        else:
            #a palvra surge pelo menos 1 vez
            word_counts[word] = 1

    #nenhuma palavra repetida excessivamente
    return False

#pequenos testes
#print(check_repeated_words("https://example.com/free/free&free/prize")) #--> True
#print(check_repeated_words("https://example.com/page")) #--> False


#nota:
#imitacao de entidades legitimas - ja foi feito acima com imitacao de dominios conhecidos
