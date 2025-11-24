import {useState} from "react";
function Body(){

    const [url, setURL] = useState('https://')
    const [response, setResponse] = useState(null)
    const [loading, setLoading] = useState(false)

    const submit = async (e) => {
        e.preventDefault()

        if (!url || url.trim() === 'https://'){
            setResponse({error: "Insira uma URL válida"})
            return
        }

        setResponse(null)
        setLoading(true)

        // Adiciona https:// se a URL não tiver protocolo
        let urlToSend = url.trim()
        if (!urlToSend.match(/^https?:\/\//i)) {
            urlToSend = `https://${urlToSend}`
        }

        try{
            const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000'
            const result = await fetch(`${apiUrl}/api/analyze`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: urlToSend })
            })

            if (!result.ok) {
                throw new Error(`Erro do servidor: ${result.status}`)
            }

            const data = await result.json()
            setResponse(data)
        } catch (e){
            setResponse({error: `Problema no servidor: ${e.message}`})
        } finally {
            setLoading(false)
        }

    }

    return (
        <>
            <main id="body">
                <div className="URL">
                    <form onSubmit={submit}>
                        <input type="text" value={url} size={url.length} onChange={(e) => {
                            setURL(e.target.value)
                        }} placeholder="https://exemplo.com"/>

                        <button type="submit">
                            submeter
                        </button>
                    </form>

                </div>
                <div className="resposta">
                    {loading && <LoadingMessage />}
                    {!loading && <Resposta response={response}/>}
                </div>

            </main>
        </>
    )
}

const LoadingMessage = () => {
    return (
        <div className="loading-container">
            <div className="spinner"></div>
            <p className="loading-text">Analisando URL...</p>
            <p className="loading-subtext">Verificando reputação e executando heurísticas de segurança</p>
        </div>
    );
};

const Resposta = ({response}) => {
    if (!response) {
        return null;
    }

    if (response.error) {
        return (
            <div className="error-simple">
                <p>Erro: {response.error}</p>
            </div>
        );
    }

    const score = response.score || 0;
    const getStatus = (score) => {
        if (score >= 80) return { text: 'MALICIOSO', color: '#d32f2f' };
        if (score >= 50) return { text: 'SUSPEITO', color: '#f57c00' };
        return { text: 'SEGURO', color: '#388e3c' };
    };

    const status = getStatus(score);

    return (
        <div className="result-simple">
            <h3>Resultado da Análise</h3>
            <p><strong>URL:</strong> {response.url}</p>
            <p>
                <strong>Score:</strong> 
                <span style={{ color: status.color, fontWeight: 'bold', marginLeft: '10px' }}>
                    {score.toFixed(2)}/100 - {status.text}
                </span>
            </p>
            {response.explanation && (
                <p><strong>Explicação:</strong> {response.explanation}</p>
            )}
            {response.reputation_checks && response.reputation_checks.length > 0 && (
                <div>
                    <strong>Verificações:</strong>
                    <ul>
                        {response.reputation_checks.map((check, index) => (
                            <li key={index}>
                                {check.source}: {check.status === 'POSITIVE' ? 'Malicioso' : 
                                                 check.status === 'NEGATIVE' ? 'Seguro' : '? Indeterminado'} 
                                ({check.reason})
                            </li>
                        ))}
                    </ul>
                </div>
            )}
        </div>
    );
};

export default Body