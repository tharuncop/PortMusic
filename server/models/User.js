const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    email: {type: String, required: true, unique: true},
    googleId: {type: String, required:true},
    name: String,
    photo: String,
    accessTokens: {
        spotify: {type: String},
        spotifyRefresh: {type: String},
        youtube: {type: String},
        youtubeRefresh: {type: String}
    },
    spotify: {
        id: String,
        displayName: String
    },
    createdAt: {type: Date, default: Date.now}
});

module.exports = mongoose.model("User", userSchema);