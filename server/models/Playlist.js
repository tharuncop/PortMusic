const mongoose = require("mongoose");

const playlistSchema = new mongoose.Schema({
    userId: {type: mongoose.Schema.Types.ObjectId, ref:"User"},
    originalUrl: {type: String, required: true},
    migratedUrl: {type: String},
    createdAt: {type: Date, default: Date.now}
});

module.exports = mongoose.model("Playlist", playlistSchema);