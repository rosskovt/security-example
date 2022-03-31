const path = require('path');
const https = require('https');
const fs = require('fs');
const express = require('express')
const helmet = require('helmet');
const passport = require('passport');
const { Strategy } = require('passport-google-oauth20');
const cookieSession = require('cookie-session');
const UserInfoError = require('passport-google-oauth20/lib/errors/userinfoerror');

require('dotenv').config();

const PORT = 3000;

const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,
  COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

const AUTH_OPTIONS = {
  callbackURL: '/auth/google/callback',
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
};

function verifyCallback(accessToken, refreshToken, profile, done) {
  console.log('Google profile', profile);
  done(null, profile);
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

//Save the session to cookie
passport.serializeUser((user, done) => {
  done(null, user.id);
});

//Read the session from the cookie
passport.deserializeUser((obj, done) => {
  // User.findById(id).then(user => {
  //   done(null, user);
  // });
  done(null, obj);
});

const app = express();

app.use(helmet());

app.use(cookieSession({
  name: 'session',
  magAge: 24 * 60 * 60 * 1000,
  keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2],
}));

app.use(passport.initialize());
app.use(passport.session());

function checkLoggedIn(req, res, next) {
  console.log('The current user is: ', req.user);
  const isLoggedIn = req.isAuthenticated() && req.user; 
  if (!isLoggedIn) {
    return res.status(401).json({
      error: 'You must log in',
    });
  }
  next();
};

app.get('/auth/google',
  passport.authenticate('google', {
    scope: ['email'],
  }), (req, res) => {
    console.log('Google email sent')
  });

app.get('/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/failure',
    successRedirect: '/',
    session: true,
  }), (req, res) => {
    console.log('Google called us back')
  });

app.get('/failure', (req, res) => {
  res.send('Failed to log in');
});

app.get('/auth/logout', (req, res) => { 
  req.logout(); //Removes req.user and clears login sessions
  return res.redirect('/');
});

app.get('/secret', checkLoggedIn, (req, res) => {
  console.log(req.url);
  return res.send('Your personal secret value is 42!');
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const options = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem'),
};

https.createServer(options, app).listen(PORT, () => {
  console.log(`listening on port ${PORT}...`);
});

