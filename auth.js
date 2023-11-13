require('dotenv').config();
const passport = require('passport');
const LocalStrategy = require('passport-local');
const bcrypt = require('bcrypt');
const { ObjectID } = require('mongodb');
const GitHubStrategy = require('passport-github').Strategy;

module.exports = function (app, myDataBase) {
  passport.serializeUser((user, done) => {
    done(null, user._id);
  });

  passport.deserializeUser((id, done) => {
    myDataBase.findOne({ _id: id }, (err, doc) => {
      if (err) return console.error(err);
      done(null, doc);
    });
  });


  passport.use(new LocalStrategy((username, password, done) => {
    myDataBase.findOne({ username: username }, (err, user) => {
      console.log(`User ${username} attempted to log in.`);
      if (err) { return done(err); }
      if (!user) { return done(null, false); }
      if (!bcrypt.compareSync(password, user.password)) { 
        return done(null, false);
      }
      return done(null, user);
    });
  }));

  app.get('/auth/github', passport.authenticate('github'));

  app.get('/auth/github/callback', passport.authenticate('github', {
    successRedirect: '/',
    failureRedirect: '/login'
  }));

  passport.use(new GitHubStrategy({
    clientID: '16d0ac1b96561321e1ee',
    clientSecret: 'ca56f5926def0afec3ad26ffbdf84d908d9a2e4c',
    callbackURL: 'https://boilerplate-advancednode.sky020.repl.co/auth/github/callback'
  }, (accessToken, refreshToken, profile, cb) => {
    console.log(profile);
    myDataBase.findAndModify(
      { id: profile.id },
      {},
      {
        $setOnInsert: {
          id: profile.id,
          name: profile.displayName || 'John Doe',
          photo: profile.photos[0].value || '',
          email: Array.isArray(profile.emails) ? profile.emails[0].value : 'No public email',
          created_on: new Date(),
          provider: profile.provider || ''
        }, $set: {
          last_login: new Date()
        }, $inc: {
          login_count: 1
        }
      },
      { upsert: true, new: true },
      (err, doc) => {
        return cb(null, doc.value);
      }
    );
  }));
};
