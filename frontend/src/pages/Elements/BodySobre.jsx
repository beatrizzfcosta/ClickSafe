
function BodySobre(){

    return(
        <>
            <main className="sobre">
                <div>
                    <h2 style={{color: '#212842'}}>Sobre o ClickSafe:</h2>

                    <p style={{textAlign: 'left', padding: '0px 30px', color: '#212842'}}>
                        Nos últimos anos, o phishing tornou-se a ameaça digital mais persistente, resultando em milhões
                        de incidentes anualmente.
                        Estes ataques baseiam-se em engenharia social para roubar dados sensíveis ou induzir
                        o clique em links maliciosos.
                        <br/>
                        Perante este cenário, o ClickSafe foi desenvolvido como uma ferramenta simples e acessível,
                        focada em promover hábitos de navegação mais seguros ao permitir que o utilizador identifique e
                        compreenda o risco de qualquer URL suspeita.
                    </p>

                    <h3 style={{color: '#212842'}}>O Que Nos Diferencia? A Explicabilidade</h3>

                    <p style={{textAlign: 'left', padding: '0px 30px', color: '#212842'}}>
                        Apesar da existência de ferramentas de deteção, estas frequentemente fornecem resultados
                        técnicos, complexos ou contraditórios (ex.: falsos negativos).
                        O ClickSafe resolve esta lacuna através de uma abordagem híbrida e transparente:
                    </p>
                    
                    <ul style={{textAlign: 'left', padding: '0px 30px', color: '#212842'}}>
                        <li style={{textAlign: 'left', padding: '0px 30px', color: '#212842'}}>
                            Análise Híbrida: Combina verificação em tempo real em Listas de Reputação (Google Safe
                            Browsing, VirusTotal) com Heurísticas que avaliam a estrutura da URL (idade do domínio,
                            presença de termos suspeitos).
                        </li>
                        <br/>
                        <li style={{textAlign: 'left', padding: '0px 30px', color: '#212842'}}>
                            Risk Score: Gera uma pontuação de risco clara (0-100%) a partir da combinação ponderada dos
                            fatores.
                        </li>
                        <br/>
                        <li style={{textAlign: 'left', padding: '0px 30px', color: '#212842'}}>
                            Explicabilidade (XAI): A nossa principal inovação. Utilizamos Inteligência Artificial
                            Explicável (XAI) para traduzir a análise técnica (heurísticas acionadas e reputação)
                            numa explicação textual compreensível.
                        </li>
                    </ul>

                    <p style={{textAlign: 'left', padding: '0px 30px', color: '#212842' }}>
                        Ao fornecer não apenas o resultado, mas a justificação por trás da classificação, o ClickSafe
                        educa o utilizador sobre os padrões de fraude, transformando a deteção em prevenção proativa e
                        aumentando a sua literacia digital.
                    </p>
                </div>
            </main>

        </>
    )
}

export default BodySobre