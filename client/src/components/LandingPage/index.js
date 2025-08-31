import React from "react";
import {Hero} from './styledComps.js'
import {Title} from './styledComps.js'
import {Subtitle} from './styledComps.js'
import {Description} from './styledComps.js'
import {CTAButton} from './styledComps.js'
import {IconsRow} from './styledComps.js'
import {Icon} from './styledComps.js'

function LandingPage(){

    const handleStartButton = () =>{
        window.location.href = 'http://localhost:4000/auth/google';
    };

    return (
    <Hero>
        <Title>PORTMUSIC</Title>
        <Subtitle>Your Music, Any Platform</Subtitle>
        <Description>
        Effortlessly transfer playlists between music services with industry-leading
        accuracy
        </Description>
        <CTAButton onClick={handleStartButton} >Start Free Transfer</CTAButton>

        <IconsRow>
        <Icon src="/assets/spotify-icon.png" alt="Spotify" />
        <Icon src="/assets/ytmusic-icon.jpg" alt="YouTube Music" />
        <Icon src="/assets/saavn-icon.png" alt="JioSaavn" />
        </IconsRow>
    </Hero>
    );
}

export default LandingPage;