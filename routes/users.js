var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

var User = require('../models/user');

/* GET users listing. */
router.get('/', function(req, res) {
  res.send('respond with a resource');
});

router.get('/register', function(req, res, next){
  res.render('register', {title: 'Register'});
});

router.get('/login', function(req, res, next){
    res.render('login', {title: 'Login'});
});


router.post('/login',
    passport.authenticate('local', {failureRedirect: "/users/login", failureFlash: "Invalid username or password"}),
    function(req, res) {
        req.flash('success', "You are now logged in");
        res.redirect('/');
    });

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.getUserById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(new LocalStrategy(function(username, password, done){
    User.getUserByUsername(username, function (err, user) {
        if(err) throw err;
        if(!user){
            return done(null, false, {message: 'Unknown user'});
        }

        User.comparePassword(password, user.password, function (err, isMatch) {
            if(err) throw err;
            if(isMatch){
                return done(null, user);
            }else{
                return done(null, false, {message:'Invalid password'});
            }
        });
    })
}));

router.post('/register', function(req, res){
    var name = req.body.name;
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;
    var password2 = req.body.password2;



    req.checkBody('name', "Name is required").notEmpty();
    req.checkBody('username', "Username is required").notEmpty();
    req.checkBody('email', "Email is required").notEmpty();
    req.checkBody('email', "Invalid email").isEmail();
    req.checkBody('password', "Password is required").notEmpty();
    req.checkBody('password2', "Password did not match").equals(req.body.password);

    var errors = req.validationErrors();

    if(errors){
        res.render('register', {errors: errors});
    }else{
       var newUser = new User({
           name: name,
           username: username,
           email: email,
           password: password
       });

       User.createUser(newUser, function (err, user) {
           if(err) throw err;
           console.log(user);
       });

       res.location('/');
       res.redirect('/');
    }

});




router.get('/logout', function(req, res){
    req.logout();
    req.flash('success', "You have been logged out");
    res.redirect('/users/login');
});

module.exports = router;
