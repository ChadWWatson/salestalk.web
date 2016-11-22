const passport = require('passport');
const LocalStrategy = require('passport-local');
const User = require('../models/User');
const config = require('../config');

const ExtractJwt = require('passport-jwt').ExtractJwt;
const JwtStrategy = require('passport-jwt').Strategy;

var localOptions = {
  usernameField: 'email',
}

var localStrategy = new LocalStrategy(localOptions, function(email, password, done) {
  User.findOne({email: email}, function(err, existingUser) {
    if(err) {return done(err)}
    if(!existingUser) { return done(null, false)}
    existingUser.comparePassword(password, function(err, isMatch){
      if(err) {return done(err)}
      if(!isMatch) { return done(null, false)}
      return done(null, existingUser);
    })
  })
})

var jwtOptions = {
  secretOrKey: config.secret,
  jwtFromRequest: ExtractJwt.fromHeader('authorization')
}


var jwtStrategy = new JwtStrategy(jwtOptions, function(payload, done){
  User.findById(payload.sub, function(err, user){
    if (err) { return done(err, false)}
    if (user) {
      done(null, user);
    } else {
      done(null, false);
    }
  });
})

passport.use(jwtStrategy);
passport.use(localStrategy);
