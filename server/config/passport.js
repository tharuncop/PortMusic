const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

// Replace with your actual Google OAuth client details
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://localhost:4000/auth/google/callback',
    },
    (accessToken, refreshToken, profile, done) => {
      // You can save user in DB here
      return done(null, profile); // later you’ll save only relevant info
    }
  )
);

// Serialize user to store in session
passport.serializeUser((user, done) => {
  done(null, user);
});

// Deserialize user from session
passport.deserializeUser((user, done) => {
  done(null, user);
});
