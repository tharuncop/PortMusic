// server/routes/auth.js
const express = require("express");
const passport = require("passport");
const router = express.Router();

// Login route
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));

router.get("/user", (req, res)=>{
    if (!req.user) return res.status(401).json({ message: "Not logged in" });
    res.send(req.user || null);
});

// Callback route
router.get("/google/callback", 
    passport.authenticate("google", { failureRedirect: "http://localhost:3001" }),
    (req, res) => {
        // Successful login, redirect to frontend dashboard
        res.redirect("http://localhost:3001/dashboard");
    }
);

// Logout route
router.get("/logout", (req, res, next) => {
    req.logout(err=>{
        if(err) return next(err);
        req.session.destroy(()=>{
            res.clearCookie("connect.sid");
            res.status(200).json({message: "Logged Out"});
        });
    });
});

module.exports = router;
