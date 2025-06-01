const express = require("express");
const cors = require('cors');
require('dotenv').config();
const connectDB = require('./config/db.js');

//setting up express
const app = express();
app.use(express.json());

//connecting server and client using express - cors
app.use(
    cors({
        origin: 'http://localhost:3001',
        credentials: true,
    })
);

//connecting the database
connectDB();

//all the routings
app.get('/auth/check', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({
        loggedIn: true,
        user: req.user,  // You can customize this to only send safe fields
        });
    } else {
        res.json({ loggedIn: false });
    }
});

//google login trigger
const passport = require('passport');
require('./config/passport');
const session = require('express-session');

// Express session middleware (must come before passport.session)
app.use(
    session({
    secret: 'your-session-secret',
    resave: false,
    saveUninitialized: false,
    })
);

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());
app.get('/auth/google', passport.authenticate('google', {
    scope: ['profile', 'email']
}));

// Callback route that Google hits after user logs in
app.get('/auth/google/callback', 
    passport.authenticate('google', {
    failureRedirect: '/',
      successRedirect: 'http://localhost:3001/dashboard', // redirect to frontend
    })
);

// API route to handle logout session
app.get('/auth/logout', (req, res) => {
    req.logout((err) => {
        if (err) return res.status(500).json({ message: 'Logout failed' });
      res.redirect('http://localhost:3001'); // back to landing page
    });
});


const PORT = process.env.BACKEND_PORT || 4000
app.listen(PORT, ()=>{
    console.log("Connected to Backend at port ", PORT);
})
