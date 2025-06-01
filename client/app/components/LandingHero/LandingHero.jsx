'use client'
import './LandingHero.css'
import {useRouter} from 'next/navigation';

function LandingHero() {

    const router = useRouter();

    const handleStartButton = () => {
      window.location.href = 'http://localhost:4000/auth/google';
    }

    return (
      <section className="landing-hero">
        <h1>PORTMUSIC</h1>
        <h3>Your Music, Any Platform</h3>
        <p>Effortlessly transfer playlists between music services with industry-leading accuracy</p>
        <button onClick={handleStartButton} >Start Free Transfer</button>

        <div className='supported-logos'>
        <img src="assets/spotify-icon.png" alt="" />
        <img src="assets/ytmusic-icon.jpg" alt="" />
        <img src="assets/saavn-icon.png" alt="" />
        </div>
      </section>
    );
}

export default LandingHero