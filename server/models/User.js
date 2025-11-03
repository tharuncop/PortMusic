// server/models/USer.js
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    spotifyId: {
        type: String,
        unique: true, 
        sparse: true, // allows for docs where this field is null
    },
    googleId: {
        type: String,
        unique: true,
        sparse: true,
    },
    displayName: {
        type: String,
        required: true,
    },

    email: {
        type: String,
        unique: true,
        sparse: true
    },

    // We will store encrypted tokens
    spotifyAccessToken: String,
    spotifyRefreshToken: String,
    googleAccessToken: String,
    googleRefreshToken: String,
});

module.exports = mongoose.model('User', UserSchema);