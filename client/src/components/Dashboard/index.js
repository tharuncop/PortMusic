// src/components/Dashboard/index.js
import React, { useState } from "react";
import axios from "axios";

import {
  Page,
  Header,
  Title,
  Sub,
  Controls,
  PrimaryButton,
  SmallButton,
  PlaylistList,
  PlaylistItem
} from "./styledComponents";

function getDisplayName(user) {
  if (!user) return "";
  return user.name || user.displayName || (user.emails && user.emails[0] && user.emails[0].value) || "User";
}

function getEmail(user) {
  if (!user) return "";
  return user.email || (user.emails && user.emails[0] && user.emails[0].value) || "";
}

const Dashboard = ({ user }) => {
  const [playlists, setPlaylists] = useState([]);

  if (!user) return null; // ProtectedRoute should prevent this, but keep safe-guard

  const hasSpotify = !!(user && ((user.hasSpotify) || (user.accessTokens && user.accessTokens.spotify)));

  const fetchSpotifyPlaylists = async () => {
    try {
      const res = await axios.get("http://localhost:4000/auth/playlists", { withCredentials: true });
      setPlaylists(res.data.items || []);
    } catch (err) {
      console.error("Failed to fetch playlists:", err?.response?.data || err.message);
      alert("Unable to load playlists. Make sure Spotify is connected.");
    }
  };

  return (
    <Page>
      <Header>
        <div>
          <Title>Welcome, {getDisplayName(user)}</Title>
          <Sub>{getEmail(user)}</Sub>
        </div>
      </Header>

      <section>
        {!hasSpotify ? (
          <>
            <Sub>You haven't connected Spotify yet. Connect to migrate playlists directly from your account.</Sub>
            <Controls>
              <a href="http://localhost:4000/auth/spotify"><PrimaryButton>Connect Spotify</PrimaryButton></a>
            </Controls>
          </>
        ) : (
          <>
            <Controls>
              <PrimaryButton onClick={fetchSpotifyPlaylists}>Fetch Spotify Playlists</PrimaryButton>
              <SmallButton as="a" href="/">Create Migration</SmallButton>
            </Controls>

            <div>
              <h3>Your playlists</h3>

              <PlaylistList>
                {playlists.length === 0 ? (
                  <PlaylistItem>No playlists loaded. Click "Fetch Spotify Playlists".</PlaylistItem>
                ) : (
                  playlists.map(pl => <PlaylistItem key={pl.id}>{pl.name}</PlaylistItem>)
                )}
              </PlaylistList>
            </div>
          </>
        )}
      </section>
    </Page>
  );
};

export default Dashboard;
