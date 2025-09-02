import React, { useState, useEffect, useRef } from "react";
import axios from "axios";
import { useHistory } from "react-router-dom";

import {
  Nav,
  Button,
  SettingsButton,
  Dropdown,
  MenuItem,
  ProfileBlock,
  StatusBadge
} from "./styledComponets";

function getDisplayName(user) {
  if (!user) return "";
  return user.name || user.displayName || (user.emails && user.emails[0] && user.emails[0].value) || "User";
}
function getEmail(user) {
  if (!user) return "";
  return user.email || (user.emails && user.emails[0] && user.emails[0].value) || "";
}

const Navbar = ({ user, onLogout }) => {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const history = useHistory();

  useEffect(() => {
    const onDocClick = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, []);

  const handleSignIn = () => (window.location.href = "http://localhost:4000/auth/google");
  const handleConnectSpotify = () => (window.location.href = "http://localhost:4000/auth/spotify");
  const handleConnectYoutube = () => (window.location.href = "http://localhost:4000/auth/youtube");

  const handleLogoutClick = async () => {
    try {
      await axios.get("http://localhost:4000/auth/logout", { withCredentials: true });
      if (typeof onLogout === "function") onLogout();
      else window.location.href = "/";
    } catch (err) {
      console.error("Logout failed:", err);
    }
  };

  const hasSpotify = !!(user && ((user.hasSpotify) || (user.accessTokens && user.accessTokens.spotify)));
  const hasYoutube = !!(user && ((user.hasYoutube) || (user.accessTokens && user.accessTokens.youtube)));

  return (
    <Nav>
      <div style={{ fontWeight: 700, cursor: "pointer" }} onClick={() => history.push("/")}>
        PORTMUSIC
      </div>

      <div style={{ position: "relative" }} ref={ref}>
        {!user ? (
          <Button onClick={handleSignIn}>Sign In</Button>
        ) : (
          <>
            {/* Settings icon button (gear) */}
            <SettingsButton
              onClick={() => setOpen((v) => !v)}
              aria-haspopup="true"
              aria-expanded={open ? "true" : "false"}
              title={getDisplayName(user)}
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true" focusable="false">
                <path d="M12 15.5A3.5 3.5 0 1 0 12 8.5a3.5 3.5 0 0 0 0 7z" fill="currentColor" opacity="0.9"/>
                <path d="M19.4 15a7.98 7.98 0 0 0 .04-1 7.98 7.98 0 0 0-.04-1l2.1-1.64a.5.5 0 0 0 .12-.63l-2-3.46a.5.5 0 0 0-.6-.22l-2.49 1a8.12 8.12 0 0 0-1.72-1l-.38-2.65A.5.5 0 0 0 13.5 2h-4a.5.5 0 0 0-.5.43l-.38 2.65c-.62.25-1.2.58-1.72 1L3.9 5.07a.5.5 0 0 0-.6.22l-2 3.46a.5.5 0 0 0 .12.63L3.5 11a7.98 7.98 0 0 0 0 2l-2.1 1.64a.5.5 0 0 0-.12.63l2 3.46c.14.24.43.34.68.22l2.49-1c.52.42 1.1.77 1.72 1l.38 2.65a.5.5 0 0 0 .5.43h4a.5.5 0 0 0 .5-.43l.38-2.65c.62-.25 1.2-.58 1.72-1l2.49 1c.25.12.54.02.68-.22l2-3.46a.5.5 0 0 0-.12-.63L19.4 15z" fill="currentColor" opacity="0.75"/>
              </svg>
            </SettingsButton>

            {open && (
              <Dropdown>
                <ProfileBlock>
                  <div style={{ fontWeight: 700 }}>{getDisplayName(user)}</div>
                  <div style={{ fontSize: 12, color: "#64748b" }}>{getEmail(user)}</div>
                </ProfileBlock>

                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  <MenuItem onClick={hasSpotify ? () => history.push("/dashboard") : handleConnectSpotify}>
                    <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-start" }}>
                      <div style={{ fontWeight: 600 }}>Spotify</div>
                      <div style={{ fontSize: 12, color: "#64748b" }}>{hasSpotify ? "Connected" : "Not connected"}</div>
                    </div>
                    <StatusBadge connected={hasSpotify}>{hasSpotify ? "On" : "Link"}</StatusBadge>
                  </MenuItem>

                  <MenuItem onClick={hasYoutube ? () => history.push("/dashboard") : handleConnectYoutube}>
                    <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-start" }}>
                      <div style={{ fontWeight: 600 }}>YouTube Music</div>
                      <div style={{ fontSize: 12, color: "#64748b" }}>{hasYoutube ? "Connected" : "Not connected"}</div>
                    </div>
                    <StatusBadge connected={hasYoutube}>{hasYoutube ? "On" : "Link"}</StatusBadge>
                  </MenuItem>

                  <MenuItem onClick={() => { setOpen(false); history.push("/profile"); }}>
                    <div>Profile</div>
                  </MenuItem>

                  <MenuItem onClick={handleLogoutClick} style={{ marginTop: 4 }}>
                    <div style={{ color: "#ef4444", fontWeight: 600 }}>Logout</div>
                  </MenuItem>
                </div>
              </Dropdown>
            )}
          </>
        )}
      </div>
    </Nav>
  );
};

export default Navbar;
