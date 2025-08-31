// server/server.js
const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const session = require("express-session");
// const passport = require("passport");

dotenv.config();
const app = express();

app.use(cors({
    origin: "http://localhost:3000",
    credentials: true
}));

app.use(session({
    secret: "secretsanta",
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // true on HTTPS only
        httpOnly: true,
        sameSite: "lax",
    },
}));


//passport strategy
const passport = require("./config/passport")
app.use(passport.initialize());
app.use(passport.session());

// Routes
const authRoutes = require("./routes/auth");
app.use("/auth", authRoutes);  // ✅ path fix

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
