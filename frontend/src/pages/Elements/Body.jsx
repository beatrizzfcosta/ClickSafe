import {useState} from "react";
function Body(){

    const [url, setURL] = useState('')
    const [response, setResponse] = useState(null)

    const submit = async (e) => {
        e.preventDefault()

        if (!url){
            setResponse({error: "Insira uma URL válida"})
            return
        }

        setResponse(null)

        try{
            const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000'
            const result = await fetch(`${apiUrl}/api/analyze`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url })
            })

            if (!result.ok) {
                throw new Error(`Erro do servidor: ${result.status}`)
            }

            const data = await result.json()
            setResponse(data)
        } catch (e){
            setResponse({error: `Problema no servidor: ${e.message}`})
        }

    }

    return (
        <>
            <main id="body">
                <div className="URL">
                    <form onSubmit={submit}>
                        <input type="text" value={url} size={url.length} onChange={(e) => {
                            setURL(e.target.value)
                        }} placeholder="Enter website or URL here"/>

                        <button type="submit">
                            submit
                        </button>
                    </form>

                </div>
                <div className="resposta">
                    <Resposta response={response}/>
                </div>

            </main>
        </>
    )
}

const Resposta = ({response}) => {
    if (!response) {
        return null;
    }

    if (response.error) {
        return (
            <div style={{color: '#800020'}}>
                <p>Erro: {response.error}</p>
            </div>
        );
    }

    return (
        <div>
            <h3>Resultado da Análise</h3>
            <p><strong>URL:</strong> {response.url}</p>
            <p><strong>Score:</strong> {response.score?.toFixed(2)}/100</p>
            {response.explanation && (
                <p><strong>Explicação:</strong> {response.explanation}</p>
            )}
            {response.reputation_checks && response.reputation_checks.length > 0 && (
                <div>
                    <strong>Verificações de Reputação:</strong>
                    <ul>
                        {response.reputation_checks.map((check, index) => (
                            <li key={index}>
                                {check.source}: {check.status} ({check.reason})
                            </li>
                        ))}
                    </ul>
                </div>
            )}
        </div>
    );
};

export default Body