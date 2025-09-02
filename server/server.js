// server/server.js
const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const session = require("express-session");
const mongoose = require("mongoose");
const MongoStore = require("connect-mongo");
const passport = require("passport");

dotenv.config();
const app = express();

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("✅ MongoDB Connected");
  } catch (err) {
    console.error("❌ Couldn't connect MongoDB:", err);
    process.exit(1);
  }
};
connectDB();

app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

app.use(
  session({
    secret: process.env.SESSION_SECRET || "secretsanta",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ client: mongoose.connection.getClient() }), // reuse mongoose client
    cookie: {
      secure: false, // true if HTTPS
      httpOnly: true,
      sameSite: "lax",
    },
  })
);

// Passport setup
require("./config/passport");
app.use(passport.initialize());
app.use(passport.session());

// Routes
const authRoutes = require("./routes/auth");
app.use("/auth", authRoutes);

const PORT = process.env.PORT || 4000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on http://localhost:${PORT}`)
);
