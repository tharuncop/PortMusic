import React from 'react';
import LandingHero from './components/LandingHero/LandingHero.jsx'
import Navbar from './components/Navbar/Navbar.jsx'

import './page.css'

function Page(){
    return (
        <div>
            <Navbar/>   
            <LandingHero/>
        </div>
    );
}

export default Page;