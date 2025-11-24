import NavBar from "./NavBar.jsx";
import clicksafe from '../../assets/ClickSafeSemBackground.png'

function Header() {

    return (
        <>
            <header>
                <div className="header">
                    <img src={clicksafe} style={{height: '150px', display: 'block', margin: '0 auto'}}/>
                    <NavBar/>
                </div>
            </header>
        </>
    )
}

export default Header