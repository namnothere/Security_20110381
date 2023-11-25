const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const helmet = require('helmet');
const passport = require('passport');
const { Strategy } = require('passport-google-oauth20');
const cookieSession = require('cookie-session');

require('dotenv').config();

const indexRouter = require('./routes/index');

const config = {
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  cookie_1: process.env.COOKIE_KEY_1,
  cookie_2: process.env.COOKIE_KEY_2
}

const AUTH_OPTS = {
  callbackURL: '/auth/google/callback',
  clientID: config.clientId,
  clientSecret: config.clientSecret
}

function verifyCallback(accessToken, refreshToken, profile, done) {
  console.log(profile);
  done(null, profile);
}

passport.use(new Strategy(AUTH_OPTS, verifyCallback));
passport.serializeUser((user, done) => {
  done(null, user.id);
})

passport.deserializeUser((id, done) => {
  // User.findById(id).then((user) => {
  //   done(null, user);
  // })
  done(null, id);
})
const app = express();

function isAuthenticated(req, res, next) {
  console.log("Current user:", req.user);
  const isLoggedIn = req.user && req.isAuthenticated();
  if (!isLoggedIn) {
    return res.status(401).json({
      error: 'You are not authorized to access this resource'
    })
  }
  next();
}

app.use(helmet());
app.use(cookieSession({
  name: 'session',
  maxAge: 24 * 60 * 60 * 1000,
  keys: [config.cookie_1, config.cookie_2]
}))
app.use(passport.initialize());
app.use(passport.session());

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', indexRouter);

app.get('/auth/google', passport.authenticate('google', {
  scope: ['email']
}));

app.get('/auth/google/callback', passport.authenticate('google', {
  successRedirect: '/',
  failureRedirect: '/failure',
  session: true
}), (req, res) => {
  console.log('google call back');
});

app.get('/auth/logout', (req, res) => {
  req.logout();
  return res.redirect('/');
})

app.get('/failure', (req, res) => {
  return res.send('L');
})


app.get('/secret', isAuthenticated, (req, res) => {
  res.send("This is a secret message");
})

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
