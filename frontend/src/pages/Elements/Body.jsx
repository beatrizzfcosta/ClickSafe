import Resposta from "./Resposta.jsx";
function Body(){

    return (
        <>
            <main id="body">
                <div className="URL">
                    <input type="text" placeholder="Enter website or URL here"/>
                </div>
                <div className="resposta">
                    <p>
                        Devido ao aumento de ataques de phishing nos últimos anos,
                        ataques que têm como objetivo enganar os utilizadores de
                        forma a que os mesmos revelem dados sensiveis ou cliquem em links maliciosos,
                        considerámos necessários desenvolver uma aplicação que ajuda-se a preveni-los.
                    </p>
                    <Resposta/>
                </div>

            </main>
        </>
    )
}

export default Body