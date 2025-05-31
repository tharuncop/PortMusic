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
    res.json({
        loggedIn: true,
        user: "Tharun",
    });
});

const PORT = process.env.BACKEND_PORT || 4000
app.listen(PORT, ()=>{
    console.log("Connected to Backend at port ", PORT);
})
