// server/routes/auth.js
const express = require("express");
const passport = require("passport");
const router = express.Router();

// Google Login route
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));

// Google Callback route
router.get("/google/callback", 
    passport.authenticate("google", { failureRedirect: "http://localhost:3000" }),
    (req, res) => {
        // Successful login, redirect to frontend dashboard
        res.redirect("http://localhost:3000/dashboard");
    }
);

// returning current user when frontend call this
router.get("/user", (req, res)=>{
    if(!req.user) return res.status(401).json({message: "No Login"});
    //sending a minimal safe user object
    const safeUser = {
        _id: req.user._id,
        email: req.user.email,
        name: req.user.name,
        photo: req.user.photo,
        hasSpotify: !!(req.user.accessTokens && req.user.accessTokens.spotify)
    };
    res.json(safeUser);
});

// Google Logout route
router.get("/logout", (req, res, next) => {
    req.logout(err=>{
        if(err) return next(err);
        req.session.destroy(()=>{
            res.clearCookie("connect.sid");
            res.status(200).json({message: "Logged Out"});
        });
    });
});

router.get("/spotify", passport.authorize("spotify", {
  scope: ["user-read-email", "playlist-read-private", "playlist-read-collaborative"]
}));

// Callback
router.get("/spotify/callback", (req, res, next) => {
  passport.authorize("spotify", (err, user, info) => {
    if (err) return next(err);

    // info object returns our conflict flag when strategy returned it
    if (info && info.spotifyConflict) {
      // Redirect back to frontend with conflict details (you can change query params)
      // IMPORTANT: not to leak the sensitive info — provide minimal guidance for the user.
      return res.redirect(`http://localhost:3000/dashboard?spotify_conflict=1`);
    }

    // If successful (user updated), just redirect back to dashboard
    return res.redirect("http://localhost:3000/dashboard");
  })(req, res, next);
});

router.get("/playlists", async (req, res)=>{
    if(!req.user || !req.user.accessTokens || !req.user.accessTokens.spotify) {
        return res.status(401).json({error: "Spotify not connected"});
    }
    try{
        const resp = await axios.get("https://api.spotify.com/v1/me/playlists",{
            headers: {Authorization: `Bearer ${req.user.accessTokens.spotify}`}
        });
        res.json(resp.data);
    } catch(err){
        console.error(err?.response?.data || err.message);
        res.status(500).json({ error: "Failed to fetch playlists" });
    }
});


module.exports = router;
