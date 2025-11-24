-- Seed data para a tabela heuristics
-- Este arquivo popula a tabela com todas as heurísticas disponíveis

INSERT OR REPLACE INTO heuristics (code, name, category, description, default_severity, default_weight) VALUES
-- Domain Heuristics
('DOMAIN_AGE', 'Idade do Domínio', 'DOMAIN', 'Verifica se o domínio é muito novo (potencialmente suspeito)', 'MEDIUM', 0.15),
('DOMAIN_EXPIRATION', 'Expiração do Domínio', 'DOMAIN', 'Verifica se o domínio está próximo do vencimento', 'LOW', 0.10),
('DOMAIN_TLD_RISK', 'Risco do TLD', 'DOMAIN', 'Avalia o risco associado ao TLD do domínio', 'MEDIUM', 0.12),
('DOMAIN_IS_IP_ADDRESS', 'Domínio é Endereço IP', 'DOMAIN', 'Verifica se o domínio é um endereço IP direto', 'HIGH', 0.25),
('DOMAIN_SIMILAR_TO_BRAND', 'Similaridade com Marca', 'DOMAIN', 'Detecta tentativas de typosquatting ou imitação de marcas', 'HIGH', 0.30),
('DOMAIN_SENSITIVE_KEYWORDS', 'Palavras-chave Sensíveis', 'DOMAIN', 'Identifica palavras-chave suspeitas no domínio', 'MEDIUM', 0.20),
('DOMAIN_MULTIPLE_SUBLEVELS', 'Múltiplos Subníveis', 'DOMAIN', 'Detecta domínios com muitos subníveis (ex: a.b.c.d.com)', 'LOW', 0.10),
('DOMAIN_HYPHENS_USAGE', 'Uso de Hífens', 'DOMAIN', 'Avalia o uso excessivo de hífens no domínio', 'LOW', 0.08),
('DOMAIN_HAS_HTTPS', 'Presença de HTTPS', 'DOMAIN', 'Verifica se o domínio possui certificado SSL válido', 'MEDIUM', 0.15),
('DOMAIN_SSL_INVALID', 'SSL Inválido', 'DOMAIN', 'Detecta problemas com certificado SSL', 'HIGH', 0.25),
('DOMAIN_GEOLOCATION_RISK', 'Risco de Geolocalização', 'DOMAIN', 'Avalia riscos baseados na localização geográfica do servidor', 'MEDIUM', 0.15),
('DOMAIN_DNS_ANOMALY', 'Anomalia DNS', 'DOMAIN', 'Identifica anomalias nas configurações DNS', 'MEDIUM', 0.18),

-- Path Heuristics
('PATH_LENGTH_EXCESSIVE', 'Comprimento Excessivo do Caminho', 'PATH', 'Detecta caminhos de URL muito longos', 'MEDIUM', 0.15),
('PATH_SUSPICIOUS_TERMS', 'Termos Suspeitos', 'PATH', 'Identifica termos suspeitos no caminho da URL', 'MEDIUM', 0.18),
('PATH_SOCIAL_ENGINEERING_TERMS', 'Termos de Engenharia Social', 'PATH', 'Identifica termos comuns em ataques de engenharia social', 'MEDIUM', 0.20),
('PATH_ADMIN_DIRECTORIES', 'Diretórios Administrativos', 'PATH', 'Identifica tentativas de acessar diretórios administrativos', 'HIGH', 0.25),
('PATH_EXECUTABLE_DISGUISED', 'Executável Disfarçado', 'PATH', 'Detecta tentativas de disfarçar arquivos executáveis', 'CRITICAL', 0.40),

-- Parameters Heuristics
('PARAMS_EXCESSIVE_NUMBER', 'Número Excessivo de Parâmetros', 'PARAMS', 'Detecta URLs com muitos parâmetros de query', 'LOW', 0.10),
('PARAMS_SENSITIVE_VARIABLES', 'Variáveis Sensíveis', 'PARAMS', 'Identifica parâmetros que podem conter dados sensíveis', 'HIGH', 0.25),
('PARAMS_LONG_OR_ENCODED_VALUES', 'Valores Longos ou Codificados', 'PARAMS', 'Detecta parâmetros com valores suspeitamente longos ou codificados', 'MEDIUM', 0.15),
('PARAMS_REDIRECT_KEYWORD', 'Palavra-chave de Redirecionamento', 'PARAMS', 'Identifica parâmetros relacionados a redirecionamentos', 'MEDIUM', 0.18),
('PARAMS_PERSONAL_DATA_INCLUDED', 'Dados Pessoais Incluídos', 'PARAMS', 'Detecta possíveis dados pessoais nos parâmetros', 'HIGH', 0.30),

-- General Heuristics
('SHORTENER_USAGE', 'Uso de Encurtador', 'GENERAL', 'Identifica uso de serviços de encurtamento de URL', 'MEDIUM', 0.15),
('MULTIPLE_REDIRECTS', 'Múltiplos Redirecionamentos', 'GENERAL', 'Detecta cadeias de redirecionamentos suspeitas', 'MEDIUM', 0.20),
('EMBEDDED_PROTOCOLS', 'Protocolos Embutidos', 'GENERAL', 'Identifica tentativas de embutir protocolos na URL', 'HIGH', 0.25),
('LANGUAGE_MIX', 'Mistura de Idiomas', 'GENERAL', 'Detecta mistura de caracteres de diferentes idiomas', 'LOW', 0.10),
('EMOJI_OR_SYMBOL_USAGE', 'Uso de Emoji ou Símbolos', 'GENERAL', 'Identifica uso de emojis ou símbolos suspeitos', 'LOW', 0.08),
('ATTRACTIVE_PHRASES', 'Frases Atrativas', 'GENERAL', 'Detecta uso de frases comuns em phishing', 'MEDIUM', 0.18),
('KEYWORD_REPETITION', 'Repetição de Palavras-chave', 'GENERAL', 'Identifica repetição excessiva de palavras-chave', 'LOW', 0.10);
