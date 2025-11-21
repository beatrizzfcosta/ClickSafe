import {BrowserRouter, Routes, Route} from 'react-router-dom';
import React from 'react';
import ReactDOM from 'react-dom/client';
import './CSS/style.css'
import Home from "./pages/Home.jsx";
import Sobre from "./pages/Sobre.jsx";

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
    <React.StrictMode>
        <BrowserRouter>
            <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/sobre" element={<Sobre />} />
            </Routes>
        </BrowserRouter>
    </React.StrictMode>
);
