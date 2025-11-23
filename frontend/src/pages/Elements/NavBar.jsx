import {Link} from "react-router-dom";

function NavBar(){

    return (
        <>
            <nav id="navBar">
                <ul className="links">
                    <li>
                        <Link to="/">Home</Link>
                    </li>
                    <li>
                        <Link to="/sobre">Sobre</Link>
                    </li>
                </ul>
            </nav>
        </>
    )
}

export default NavBar