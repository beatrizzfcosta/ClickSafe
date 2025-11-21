import {useState} from "react";
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
            const result = app.py [url]

            setResponse(result)
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