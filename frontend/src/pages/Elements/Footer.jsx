
function Footer(){
    return (
        <>
            <footer>
                <section id="Grupo">
                    <h3>Trabalho realizado por:</h3>

                    <div className="membros">
                        <Membro
                            nome="Beatriz Costa"
                            email="Beatriz_Costa@iscte-iul.pt"
                        />
                        <Membro
                            nome="Ema Reis"
                            email="Ema_Reis@iscte-iul.pt"
                        />
                        <Membro
                            nome="Letícia Cascais"
                            email="Leticia_Cascais@iscte-iul.pt"
                        />
                        <Membro
                            nome="Mariana Capela"
                            email="Mariana_Capela@iscte-iul.pt"
                        />
                        <Membro
                            nome="Nádia Gavancha"
                            email="Nadia_Gavancha@iscte-iul.pt"
                        />
                    </div>
                </section>
            </footer>
        </>
    )
}

const Membro = ({nome, email}) => (
    <div className="seccao-membro">
        <p>{nome}</p>
        <p>{email}</p>
    </div>
);

export default Footer