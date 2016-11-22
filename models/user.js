const mongoose = require('mongoose');
var Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

var validateEmail = function(email) {
  return (/\S+@\S+.\S+/).test(email);
}

var userSchema = new Schema({
  email: {
    type: String,
    unique: true,
    lowercase: true,
    require: 'Email is required',
    validate: [validateEmail, 'Please enter a valid email']
  },
  password: {
    type: String
  }
});

userSchema.pre('save', function(next) {
  var user = this;
  if(user.isNew || user.isModified('password')) {
    bcrypt.genSalt(10, function(err, salt){
      if(err) { return next(err)}
      bcrypt.hash(user.password, salt, null, function(err, hash){
        if(err) { return next(err)}
        user.password = hash;
        next();
      })
    })
  } else {
    next();
  }
});

userSchema.methods.comparePassword = function(candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, function (err, isMatch) {
    if (err) { return cb(err) }
    cb(null, isMatch);
  })
}

module.exports = mongoose.model('user', userSchema);
