// server/config/passport.js
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const SpotifyStrategy = require("passport-spotify").Strategy;
const User = require("../models/User");

//Google authorization and updation of PortMusic Db
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:4000/auth/google/callback"
}, 
  async (accessToken, refreshToken, profile, done) => {
    try{
      //find or create user buy googleID or email
      const email = profile.emails && profile.emails[0] && profile.emails[0].value;
      let user = await User.findOne({googleId: profile.id}) || (email && await User.findOne({email}));

      if(!user){
        user = await User.create({
          googleId: profile.id,
          email,
          name: profile.displayName,
          photo: profile.photos && profile.photos[0] && profile.photos[0].value
        });
      } else {
        //update any changed profile info
        user.name = profile.displayName || user.name;
        user.photo = (profile.photos && profile.photos[0] && profile.photos[0].value) || user.photo;
        await user.save();
      }
      done(null, user);
    } catch(err){
      done(err, null);
    }
}));


//Spotify Authorization and updation of project Db
passport.use(new SpotifyStrategy({
  clientID: process.env.SPOTIFY_CLIENT_ID,
  clientSecret: process.env.SPOTIFY_CLIENT_SECRET,
  callbackURL: process.env.SPOTIFY_CALLBACK_URL || process.env.SPOTIFY_REDIRECT_URI,
  passReqToCallback: true
},
async (req, accessToken, refreshToken, expires_in, profile, done) => {
  try {
    // Must be logged-in via Google (req.user exists). If not, reject linking.
    if (!req.user || !req.user._id) {
      return done(null, false, { message: "Must be logged in to link Spotify." });
    }

    // 1) Is this Spotify account already linked to another user?
    const existing = await User.findOne({ "spotify.id": profile.id });

    if (existing) {
      // If existing is the same as current user, update tokens and return success.
      if (existing._id.toString() === req.user._id.toString()) {
        existing.accessTokens = existing.accessTokens || {};
        existing.accessTokens.spotify = accessToken;
        if (refreshToken) existing.accessTokens.spotifyRefresh = refreshToken;
        existing.spotify = existing.spotify || {};
        existing.spotify.id = profile.id;
        existing.spotify.displayName = profile.displayName;
        await existing.save();
        return done(null, existing);
      }

      // If it's linked to a different user, that's a conflict.
      // Don't silently reassign. Return an info object via done(null, req.user, { conflict: true, otherUserId: existing._id })
      return done(null, req.user, { spotifyConflict: true, conflictUserId: existing._id, conflictUserEmail: existing.email });
    }

    // 2) Otherwise, link Spotify to the currently logged-in DB user
    const user = await User.findById(req.user._id);
    if (!user) return done(new Error("Logged-in user not found"));

    user.spotify = { id: profile.id, displayName: profile.displayName };
    user.accessTokens = user.accessTokens || {};
    user.accessTokens.spotify = accessToken;
    if (refreshToken) user.accessTokens.spotifyRefresh = refreshToken;
    await user.save();

    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

//storing only user id in session(small)
passport.serializeUser((user, done) => {done(null, user._id)} );

// restoring user from DB on eacch request
passport.deserializeUser(async (id, done)=>{
  try{
    const user = await User.findById(id);
    done(null, user);
  } catch(err){
    done(err, null);
  }
});

module.exports = passport;
