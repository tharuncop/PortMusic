require('dotenv').config();
const session = require('express-session');
const MongoStore = require('connect-mongo');
const axios = require('axios');
const cors = require('cors');
const querystring = require('querystring');
const express = require('express');
const {google} = require('googleapis');
const connectDB = require('./config/db');
const User = require('./models/User');
const {encrypt, decrypt} = require('./utils/security');
const { error } = require('console');

const app = express();
const PORT = 4000;

connectDB();

// Enhanced CORS configuration
app.use(
    cors({
        origin: process.env.CLIENT_URL,
        credentials: true,
    })
);

// Parse JSON bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CRITICAL FIX: Session configuration for OAuth flows
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: true, // Changed to true for OAuth flows
        saveUninitialized: true, // Changed to true
        store: MongoStore.create({
            mongoUrl: process.env.MONGO_URI,
            ttl: 14 * 24 * 60 * 60 // 14 days
        }),
        cookie: {
            maxAge: 1000 * 60 * 60 * 24, // 1 day
            sameSite: 'lax', // Changed from 'none' to 'lax' for local development
            secure: false, // false for local development
            httpOnly: true,
        }
    })
);

// Session debugging middleware
app.use((req, res, next) => {
    console.log('=== SESSION DEBUG ===');
    console.log('Session ID:', req.sessionID);
    console.log('Session userId:', req.session.userId);
    console.log('URL:', req.url);
    console.log('=====================');
    next();
});

app.get('/', (req, res)=>{
    res.send("At home route of server");
});

// -- GOOGLE AUTHENTICATION --
const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
);

app.get('/auth/google', (req, res)=>{
    const scopes = [
        'https://www.googleapis.com/auth/userinfo.profile',
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/youtube',
        'https://www.googleapis.com/auth/youtube.upload'
    ];
    const url = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: scopes,
        prompt: 'consent',
    });
    res.redirect(url);
});

app.get('/auth/google/callback', async(req, res)=>{
    const {code} = req.query;
    try{
        const {tokens} = await oauth2Client.getToken(code);
        oauth2Client.setCredentials(tokens);
        const oauth2 = google.oauth2({version: 'v2', auth: oauth2Client});
        const {data} = await oauth2.userinfo.get();

        const user = await User.findOneAndUpdate(
            { $or: [{ googleId: data.id }, { email: data.email }] },
            {
                googleId: data.id,
                email: data.email,
                displayName: data.name,
                googleAccessToken: encrypt(tokens.access_token),
                ...(tokens.refresh_token && {googleRefreshToken: encrypt(tokens.refresh_token) }),
            },
            {upsert: true, new: true}
        );

        req.session.userId = user._id.toString();
        console.log('Saved/Updated Google User:', user);
        
        // Force session save before redirect
        req.session.save((err) => {
            if (err) {
                console.error('Session save error:', err);
            }
            res.redirect(`${process.env.CLIENT_URL}`);
        });
    } catch (error){
        console.error('Error getting Google tokens: ', error.message);
        res.redirect(`${process.env.CLIENT_URL}?error=google_auth_failed`);
    }
});

// -- SPOTIFY AUTHENTICATION - UPDATED WITH SESSION PERSISTENCE --
app.get('/auth/spotify', (req, res)=>{
    console.log('Spotify auth - Session userId: ', req.session.userId);
    
    if (!req.session.userId) {
        console.log('Spotify link failed: User not authenticated');
        return res.redirect(`${process.env.CLIENT_URL}?error=not_logged_in`);
    }

    const scope = 'playlist-read-private playlist-modify-public playlist-modify-private user-read-private user-read-email';
    
    // Store session ID in state parameter to recover it later
    const state = req.sessionID;
    
    const authUrl = 'https://accounts.spotify.com/authorize?' +
    querystring.stringify({
        response_type: 'code',
        client_id: process.env.SPOTIFY_CLIENT_ID,
        scope: scope,
        redirect_uri: process.env.SPOTIFY_REDIRECT_URI,
        state: state, // Pass session ID as state
        show_dialog: false, // Set to false for better UX
    });
    
    // Force save session before redirect
    req.session.save((err) => {
        if (err) {
            console.error('Session save error:', err);
            return res.redirect(`${process.env.CLIENT_URL}?error=session_error`);
        }
        res.redirect(authUrl);
    });
});

app.get('/auth/spotify/callback', async(req, res)=>{
    const code = req.query.code || null;
    const state = req.query.state; // Get the session ID from state parameter
    
    console.log('Spotify callback - Current Session ID:', req.sessionID);
    console.log('Spotify callback - State parameter (original session):', state);

    // If we have a state parameter, use THAT session instead of the current one
    if (state && state !== req.sessionID) {
        console.log('Session mismatch - restoring original session...');
        
        // Get the original session from the store
        req.sessionStore.get(state, async (err, sessionData) => {
            if (err) {
                console.error('Error retrieving original session:', err);
                return res.redirect(`${process.env.CLIENT_URL}?error=session_recovery_failed`);
            }
            
            if (sessionData && sessionData.userId) {
                console.log('Original session found, userId:', sessionData.userId);
                
                // Destroy the current (wrong) session
                req.session.destroy(async (destroyErr) => {
                    if (destroyErr) {
                        console.error('Error destroying current session:', destroyErr);
                    }
                    
                    // Create a new session with the original session data
                    req.sessionStore.createSession(req, {
                        ...sessionData,
                        id: state // Use the original session ID
                    });
                    
                    req.session.userId = sessionData.userId;
                    req.sessionID = state;
                    
                    console.log('Session restored, proceeding with Spotify token exchange...');
                    await exchangeSpotifyToken(code, sessionData.userId, req, res);
                });
            } else {
                console.log('No session data found for state:', state);
                res.redirect(`${process.env.CLIENT_URL}?error=no_session`);
            }
        });
    } else if (req.session.userId) {
        // Session is still valid, proceed normally
        console.log('Using current session, userId:', req.session.userId);
        await exchangeSpotifyToken(code, req.session.userId, req, res);
    } else {
        console.log('No session and no state parameter');
        res.redirect(`${process.env.CLIENT_URL}?error=no_session`);
    }
});

// Helper function for Spotify token exchange
// Helper function for Spotify token exchange
async function exchangeSpotifyToken(code, userId, req, res) {
    try {
        const response = await axios({
            method: 'post',
            url: 'https://accounts.spotify.com/api/token',
            data: querystring.stringify({
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: process.env.SPOTIFY_REDIRECT_URI,
            }),
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic ' + (Buffer.from(process.env.SPOTIFY_CLIENT_ID + ':' + process.env.SPOTIFY_CLIENT_SECRET)).toString('base64'),
            },
        });

        const {access_token, refresh_token} = response.data;
        const profileResponse = await axios.get('https://api.spotify.com/v1/me', {headers: {Authorization: `Bearer ${access_token}`}});
        const profileData = profileResponse.data;

        const user = await User.findByIdAndUpdate(
            userId,
            {
                spotifyId: profileData.id,
                spotifyAccessToken: encrypt(access_token),
                ...(refresh_token && {spotifyRefreshToken: encrypt(refresh_token)})
            },
            { new: true }
        );

        console.log('Linked Spotify Account:', user);
        
        // Force session save before final redirect
        req.session.save((err) => {
            if (err) {
                console.error('Final session save error:', err);
            }
            console.log('Redirecting to client with restored session');
            res.redirect(`${process.env.CLIENT_URL}`);
        });
    } catch(error) {
        console.error('Error getting spotify tokens: ', error.response ? error.response.data : error.message);
        res.redirect(`${process.env.CLIENT_URL}?error=spotify_auth_failed`);
    }
}

// API Routes
app.get('/api/me', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    try {
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({
            id: user._id,
            displayName: user.displayName,
            email: user.email,
            hasSpotify: !!user.spotifyId,
            hasGoogle: !!user.googleId
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

const refreshSpotifyToken = async (userId) => {
    console.log('Attempting to refresh token for user:', userId);

    try {
        const user = await User.findById(userId);
        if(!user || !user.spotifyRefreshToken){
            throw new Error('No spotify refresh token for the user');
        }

        const refreshToken = decrypt(user.spotifyRefreshToken);
        if(!refreshToken) {
            throw new Error('Failed to decrypt refresh token');
        }

        const response = await axios({
            method: 'post',
            url: 'https://accounts.spotify.com/api/token',
            data: querystring.stringify({
                grant_type: 'refresh_token',
                refresh_token: refreshToken,
            }),
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic ' + (Buffer.from(process.env.SPOTIFY_CLIENT_ID + ':' + process.env.SPOTIFY_CLIENT_SECRET)).toString('base64'),
            },
        });

        const {access_token} = response.data;
        await User.findByIdAndUpdate(userId, {
            spotifyAccessToken: encrypt(access_token),
        });

        console.log('Successfully refreshed Spotify Token');

        return access_token;
    
    } catch (error) {
        console.error('Error in refreshSpotifyToken helper: ', error);
        throw new Error('Token refresh Failed.');
    }
};

// FUNCTION TO REFRESH GOOGLE TOKEN
const refreshGoogleToken = async (userId) => {
    console.log('Attempting to refresh Google token for user:', userId);

    try {
        const user = await User.findById(userId);
        if(!user || !user.googleRefreshToken){
            throw new Error('No Google refresh token for user,');
        }

        const refreshToken = decrypt(user.googleRefreshToken);
        if(!refreshToken) {
            throw new Error('Failed to decrypt Google refresh token.');
        }

        oauth2Client.setCredentials({
            refresh_token: refreshToken
        });

        // Now, Exchanging refresh token for an access token
        const {credentials} = await oauth2Client.refreshAccessToken();
        const newAccessToken = credentials.access_token;

        await User.findByIdAndUpdate(userId, {
            googleAccessToken: encrypt(newAccessToken)
        });

        console.log('Successfully refreshed Google token');

        return newAccessToken;

    } catch (error) {
        console.error('Error in refreshGoogleToken helper:', error);
        throw new Error('Google token refresh failed.');
    }

};



// API ROUTES FOR PLAYLIST FETCHING
app.get('/api/spotify/playlists', async(req, res) => {
    if(!req.session.userId){
        return res.status(401).json({error: 'Not Authenticated'});
    }

    const getPlaylists = async (token) => {
        return axios.get('https://api.spotify.com/v1/me/playlists', {
            headers: {'Authorization': `Bearer ${token}`},
            params: {'fields': 'items(id, name, tracks.total)' }
        });
    };

    try{
        // find user in the database
        const user = await User.findById(req.session.userId);
        if(!user || !user.spotifyAccessToken){
            return res.status(404).json({error: 'Spotify account not connected.'});
        }

        const accessToken = decrypt(user.spotifyAccessToken);
        if(!accessToken) {
            return res.status(500).json({error: 'Failed to decrypt token'});
        }

        try {
            const {data} = await getPlaylists(accessToken);
            res.json(data.items);
        } catch (error) {
            if(error.response && error.response.status === 401){
                console.log('Spotify token expired. Refreshing...');
                try {

                    const newAccessToken = await refreshSpotifyToken(req.session.userId);

                    console.log('Retryig playlist fetch with new token...');
                    const {data} = await getPlaylists(newAccessToken);
                    res.json(data.items);

                } catch (refreshError) {
                    console.error('Failed to refresh token or retry fetch:', refreshError.message);
                    res.status(500).json({error: 'Failed to refresh token.'});
                }
            } else {
                throw error;
            }
        }

    } catch (error) {
        console.log('Error fetching spotify playlists:', error.response ? error.response.data : error.message);

        res.status(500).json({error: 'Failed to fetch playlists'});
    }
});

app.post('/api/transfer', async (req, res) => {
    console.log('Request body: ', req.body);

    if(!req.session.userId){
        return res.status(401).json({error: 'Not Authenticated for Transfer'});
    }

    const {playlistId, playlistName} = req.body;
    const userId = req.session.userId;


    try {

        const user = await User.findById(userId);
        if(!user || !user.spotifyAccessToken){
            return res.status(404).json({error: 'Spotify account not connected'});
        }

        let spotifyToken = decrypt(user.spotifyAccessToken);

        let allTracks = [];
        let spotifyApiUrl = `https://api.spotify.com/v1/playlists/${playlistId}/tracks`;

        console.log(`Fetching tracks for playlist: ${playlistName}`);

        while(spotifyApiUrl){
            let attempt = 1;
            try {
                const {data} = await axios.get(spotifyApiUrl, {
                    headers: {'Authorization': `Bearer ${spotifyToken}`},
                    params: {'fields': 'items(track(name, artists(name))), next'}
                });

                allTracks.push(...data.items);

                // Getting Url for next batch of songs
                spotifyApiUrl = data.next;

            } catch (err) {

                if(err.response && err.response.status === 401 && attempt === 1){
                    console.log('Spotify token expired during track fecth, refreshing...');
                    spotifyToken = await refreshSpotifyToken(userId);

                    attempt = 2;
                } else {
                    throw err;
                }
            }
        }

        // Processing tracks && logging them
        const trackQueries = allTracks.map(item =>{
            if(!item.track) return null;
            const trackName = item.track.name;
            const artistName = item.track.artists.map(artist => artist.name).join(' ');
            return `${trackName} ${artistName}`;

        }).filter(Boolean); //Filter out any nulls

        console.log(`Found ${trackQueries.length} tracks. First 5:`);
        console.log(trackQueries.slice(0, 5));


        // YOUTUBE AUTHENTICATION
        console.log('Authenticating with Google/Youtube...');

        if(!user.googleAccessToken){
            return res.status(404).json({error: 'Youtube not connected'});
        }

        let googleToken = decrypt(user.googleAccessToken);
        oauth2Client.setCredentials({
            access_token: googleToken
        });
        let googleRefreshToken = user.googleRefreshToken ? decrypt(user.googleRefreshToken) : null;

        const userOAuthClient = new google.auth.OAuth2(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET,
            process.env.GOOGLE_REDIRECT_URI
        );

        userOAuthClient.setCredentials({
            access_token: googleToken,
            refresh_token: googleRefreshToken
        });

        let youtube = google.youtube({version: 'v3', auth: userOAuthClient});

        try {

            await youtube.channels.list({part: 'snippet', mine: true});
            console.log('Google token is valid');

        } catch (error) {

            if(error.response && (error.response.status === 401 || error.response.status === 403)) {
                console.log('Google Token expired. Refreshing...');

                try {

                    const newGoogleToken = await refreshGoogleToken(userId);

                    userOAuthClient.setCredentials({
                        access_token: newGoogleToken,
                        refresh_token: googleRefreshToken
                    });

                    // Re-initializing the youtube object: 
                    console.log('Re-initializig Youtube service with new token...');
                    youtube = google.youtube({ version: 'v3', auth: userOAuthClient });

                    console.log('Youtube re-authenticated with new token');

                } catch (refreshError){
                    console.error('Failed to refresh Google token:', refreshError);
                    return res.status(500).json({error: 'Failed to refresh Googel token'});

                }

            } else {
                throw error;
            }
        }

        console.log('Youtube successfully authenticated. Ready to create playist.');

        // TODO : Create, Search & add tracks to playlist
        //****** */ CREATING A YOUTUBE PLAYLIST *****

        const playlistTitle = `${playlistName} (from portmusic)`;
        console.log(`Creating new Youtube playlist: ${playlistTitle}`);
        const playlistResponse = await youtube.playlists.insert({
            part: 'snippet,status',
            requestBody: {
                snippet: {
                    title: playlistTitle,
                    description: `Transferred from spotify playlist "${playlistName}. Created by PortMusic. `,
                },
                status: {
                    privacyStatus: 'private',
                }
            },
        });


        const newPlaylistId = playlistResponse.data.id;
        const newPlaylistUrl = `https://www.youtube.com/playlist?list=${newPlaylistId}`;
        console.log(`Playlist created! ID: ${newPlaylistId}`);

        // *** SEARCH AND ADD TRACKS *** //
        console.log('Starting to search and tracks to Youtube playlist...');
        let addedCount = 0;
        let failedCount = 0;

        for(const query of trackQueries) {
            try {

                const searchResponse = await youtube.search.list({
                    part: 'snippet',
                    q: query,
                    type: 'video',
                    maxResults: 1, // Get only the top result
                });

                if(searchResponse.data.items.length > 0) {

                    const videoId = searchResponse.data.items[0].id.videoId;

                    // post above response into newly created playlist
                    await youtube.playlistItems.insert({
                        part: 'snippet',
                        requestBody: {
                            snippet: {
                                playlistId: newPlaylistId,
                                resourceId: {
                                    kind: 'youtube#video',
                                    videoId: videoId,
                                },
                            },
                        },
                    });
                    console.log(`Added: ${query}`);
                    addedCount++;

                } else {
                    console.log(`No result found for: ${query}`);
                    failedCount++;
                }

            } catch (addError) {
                console.error(`Failed to add: ${query}`, addError.message);
            }
        }

        console.log('--- TRANSFER COMPLETE ---');
        console.log(`Successfully added: ${addedCount} tracks`);
        console.log(`Failed to find/add ${failedCount} tracks`);
        

        // Final success response
        res.json({
            message: 'Transfer complete',
            playlistUrl: newPlaylistUrl,
            added: addedCount,
            failed: failedCount,
        });
        
    } catch (error){
        console.error('Error in api/transfer route', error.message);
        if(error.response) {
            console.error('Youtube API response: ', error.response.data);
            console.error('Status:', error.response.status);
        }
        res.status(500).json({error: 'Transfer failed.'});
    }

});


app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ error: 'Failed to log out' });
        }
        res.clearCookie('connect.sid');
        res.status(200).json({ message: 'Logged out successfully' });
    });
});


app.listen(PORT, ()=>{
    console.log(`✅ Server is listening on http://localhost:${PORT}`);
});