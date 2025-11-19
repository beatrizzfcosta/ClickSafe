import {useState} from "react";
import axios from 'axios';

const URL_ANALYSIS = "http://localhost:8000/analise/"
function Body(){

    const [url, setURL] = useState('')
    const [response, setResponse] = useState(null)

    const submit= async (e)=>{
        e.preventDefault()

        if (!url){
            setResponse({error: "Insira uma URL válida"})
            return
        }

        setResponse(null)

        try{
            const result = await axios.post(URL_ANALYSIS, {url: url})

            setResponse(result.data)
        } catch (e){
            setResponse({error: "Problema no servidor"})
        }

    }

    return (
        <>
            <main id="body">
                <div className="URL">
                    <form>
                        <input type="text" value={url} onChange={(e) => {
                            setURL(e.target.value)
                        }} placeholder="Enter website or URL here"/>

                        <button type={submit}>
                            submit
                        </button>
                    </form>

                </div>
                <div className="resposta">
                    <p>
                    Devido ao aumento de ataques de phishing nos últimos anos,
                        ataques que têm como objetivo enganar os utilizadores de
                        forma a que os mesmos revelem dados sensiveis ou cliquem em links maliciosos,
                        considerámos necessários desenvolver uma aplicação que ajuda-se a preveni-los.
                    </p>
                    <Resposta response={response}/>
                </div>

            </main>
        </>
    )
}

const Resposta = ({response}) => (
        <div>
            <p>{response}</p>
        </div>
);

export default Body