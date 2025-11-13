#imports necessários
from datetime import datetime #para poder ver datas
import whois  #para consulta de informações de domínio
import tldextract  #para extrair partes do domínio
import dns.resolver #para verificar registros DNS
import ssl  #para verificar certificados SSL
import urllib.parse  #para analisar URLs
import requests  #para fazer requisições HTTP


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


#idade do dominio - verificar se é muito recente
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


#idade do dominio - verificar se esta prestes a expirar 
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
print (check_domain_age_expiring("zlnewb.bond"))
print (check_domain_age_recent("zlnewb.bond"))



#dominios de nivel superior (TLD) suspeitos (.tk, .ml, .ga, .cf, .gq)


#Utiliza endereco IP em vez de nome de dominio


#Similaridade com dominios conhecidos (typosquatting)


#multiplos subniveis de dominio ou uso de hifens


#ausencia de HTTPS ou certificado SSL invalido - nao seguro


#ausencia de registos DNS


#localização suspeita do servidor (pais de alto risco ou diferente do esperado)


#-------------------Analise do caminho --------------------

#uso de muitos subdiretorios ou caminhos longos

#subdiretorios administrativos (ex: /admin/, /login/, /secure/) - nao devem estar acessiveis publicamente

#uso de palavras suspeitas no caminho (ex: "login", "secure", "update")

#extensoes duplas ou executaveis disfarcadas (ex: .php.jpg, .exe)

#termos de engenharia social no caminho 

#-------------------Analise dos parametros --------------------

#uso excessivo de parametros na URL - numero excessivo

#variaveis sensiveis (ex token, auth, sessionid) na URL

#valores demasiado longos ou codificados

#parametros de redirecionamento

#inclusao de dados pessoasis (ex: nome, email) na URL


#-------------------Analise encurtadores e redirecionamentos --------------------

#uso de servicos de encurtamento de URL (bit.ly, tinyurl) - pode ocultar o destino real

#redirecionamentos multiples ou cadeias de redirecionamento

#urls com protocolos embutidos


#-------------------Padroes de engenharia social --------------------

#mistura de idiiomas

#uso de simbolos ou emojis na URL

#frases apelativas ou urgentes 

#repeticao de palavras 

#imitacao de marcas conhecidas




#funcao para retornar vetor de booleanos com os diferentes heuristicas analisadas
#def analyze_url_heuristics(url):
