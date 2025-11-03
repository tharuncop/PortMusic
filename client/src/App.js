// client/scrc/App.js
import React, { useState, useEffect } from 'react';
import axios from 'axios';
axios.defaults.withCredentials=true;
const BACKEND_URL = 'http://localhost:4000';    

function App(){
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isFetching, setIsFetching] = useState(false);
  const [playlists, setPlaylists] = useState([]);

  const [transferringId, setTransferringId] = useState(null);



  useEffect(()=>{
    const fetchUser = async() => {
      try{
        const {data} = await axios.get(`${BACKEND_URL}/api/me`);
        setUser(data);
      } catch(error){
        console.log('No user logged in.');
      }
      setLoading(false);
    };
    fetchUser();
  }, []);

  // Auth button functions
  const connectGoogle = () => {
    window.location.href = `${BACKEND_URL}/auth/google`;
  };

  const connectSpotify = () => {
    window.location.href = `${BACKEND_URL}/auth/spotify`;
  };

  const handleLogout = async() => {
    try{
      await axios.post(`${BACKEND_URL}/api/logout`);
      setUser(null);
    } catch(err){
      console.log('Failed to log out', err);
    }
  };

  const fetchSpotifyPlaylists = async() => {
    setIsFetching(true);
    try{
      const {data} = await axios.get(`${BACKEND_URL}/api/spotify/playlists`);
      setPlaylists(data);
    } catch(err) {
      
      // Checking if error is 401 (Token expired)
      console.error('Error fetching playlists:', err.response ? err.response.data : err.message);
    }
    setIsFetching(false);
  };

  // Playlist Transfer handling functions
  const handleTransfer = async (playlistId, playlistName) => {
    setTransferringId(playlistId);
    console.log(`Starting transfer for: ${playlistName} (${playlistId})`);

    try {
      // Using POST beacuse this action changes data (creates playlist)
      const {data} = await axios.post(`${BACKEND_URL}/api/transfer`, {
        playlistId: playlistId,
        playlistName: playlistName
      });

      console.log('Transfer complete!', data);

    } catch (err){
      console.error('Error during transfer: ', err);
    }

    setTransferringId(null);
  };

  if(loading){
    return <div>Loading...</div>
  }

  return (
    <div style={{padding: '50px', fontFamily: 'Arial, sans-serif'}}>

      <h1>PORTMUSIC</h1>
      
      {!user ? (
      <>
        <p>Please Login with google to start</p>
        <button onClick={connectGoogle}>Login with Google</button>
      </> 
      ) : (
        <>
          <h2>Welcome, {user.displayName}!</h2>
          <button onClick={handleLogout}> Logout </button>

        <h3>Your Connections:</h3>
        <p>
          <strong>Google:</strong> Connected ({user.email})
        </p>
        <p>
          <strong>Spotify:</strong>
          {user.hasSpotify ? ('Connected')
          : (
            <button onClick={connectSpotify}> Connect Spotify</button>
          )
          }
        </p>

          {/* playlist logic here*/}
          {user.hasSpotify && (
            <div style={{marginTop: '30px'}}>
              <h3>Your Spotify Playlists</h3>
              <button onClick={fetchSpotifyPlaylists} disabled={isFetching}>
                {isFetching ? 'Loading...' : 'Fetch Playlists'}
              </button>

            {playlists.length > 0 && (
              <ul style={{listStyle: 'none', paddingLeft: 0}}>
                {playlists.map(playlist => (
                  <li key={playlist.id} style={{border: '1px solid #ccc', padding: '10px', margin: '5px 0', display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                    <div>
                      <strong>{playlist.name}</strong>
                      <span style={{color: '#555'}}> ({playlist.tracks.total}) </span>
                    </div>
                    <button onClick={()=> handleTransfer(playlist.id, playlist.name)} disabled={transferringId === playlist.id}>
                      Transfer to Youtube
                    </button>
                  </li>
                ))}
              </ul>
            )}
            </div>
          )}
          {/* END OF PLAYLIST FETCH LOGIC*/}
        </>
      ) }

    </div>

  );

}

export default App;