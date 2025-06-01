# PortMusic

It is a simple web application that aims in transporting music playlists from one music platform to another. Did this side project so that I could transport my huge load of Spotify playlist to another platforms. Used NextJS for Client-side & ExpressJS for Server-side.

# CLIENT PORT SETUP

-> Although I have used PORT-3001 for client. Beware that NextJS considers PORT-3000 by default. So make sure what port your computer is running the client on, and kindly modify the port details while importing via CORS

# SETUP YOUR GOOGLE OAUTH CREDENTIALS

-> ADD YOUR GOOGLE OAUTH CREDENTIALS BY CREATING A '.env' FILE IN PORTMUSIC/SERVER
->BEWARE NOT TO EXPOSE YOUR OAUTH CREDENTIALS DIRECTLY IN JS FILE. (ALWAYS IMPORT IT THROUGH process.env.**\_\_**)
