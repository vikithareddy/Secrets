//reuire the packages
require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
//const encrypt = require("mongoose-encryption");
//const md5 = require("md5");
//const bcrypt = require("bcrypt");
//const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

//use express-session to initiliaze a session
app.use(session({
  secret: "Some secret.",
  resave: false,
  saveUninitialized: false
}));

//initiliaze passport
app.use(passport.initialize());

//use session to set up the passport
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

//add the passport local mongoose plugin to userSchema
userSchema.plugin(passportLocalMongoose);

//encrypt using the secret string and mongoose-encryption package. encrypt only the password
//the password will be encrypted when you call save and decrypted when you call find
//userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]}); //add this BEFORE creating the mongoose model


const User = new mongoose.model("User", userSchema);

//passport local configuration. 1. create strategy 2. serialize 3. deserialize
passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", function(req, res) {
  res.render("home");
});

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});


////////////////////////////////////////USING PASSPORT////////////////////////////////////

//REGISTER
app.post("/register", function(req, res){
  //register user using passport-local-mongoose
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err) {
      console.log(err);
      res.redirect("/register"); //redirect to register page so they can try to login again
    } else {
      //only authenticated when the session and cookies are set up adn their current logged in session is saved
      //i.e. as long as they are logged in they can view the secrets page (the cookies are set up to keep track of their session)
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

//GET SECRETS
app.get("/secrets", function(req, res) {
  //if a user is already logged in, render the secrets page
  if(req.isAuthenticated()) {
    res.render("secrets");
    //otherwise, redirect them to the login page
  } else {
    res.redirect("/login");
  }
});


//LOGOUT
app.get("/logout", function(req, res) {
  //logout the user and redirect to homepage
  req.logout();
  res.redirect("/");
});


//LOGIN
app.post("/login", function(req, res){
  const user = new User ({
    username: req.body.username,
    password: req.body.password
  });

  //use passport to login in the user and authenticate them
  req.login(user, function(err){
    if (err){
      console.log(err);
    } else {
      //authenticate the user
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });

});


////////////////////////////////////////USING PASSPORT////////////////////////////////////



//////////////////////////////////////////USING BCRYPT////////////////////////////////////

//post request to register page
/*app.post("/register", function(req, res) {
  //hashing and salting using bcrypt
  bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    //create a new user document
    const newUser = new User({
      email: req.body.username,
      //password: md5(req.body.password) //use md5 to hash the password
      password: hash
    });

    //save the new user and render the page if there are no errors
    newUser.save(function(err) {
      if (err) {
        console.log(err);
      } else {
        res.render("secrets");
      }
    });
  });

});


//post request to login route
app.post("/login", function(req, res){
  const username = req.body.username;
  //const password = md5(req.body.password); //hash it using md5 to compare to the previously hashed password
  const password = req.body.password;

  User.findOne({email: username}, function(err, foundUser) {
    if (err){
      console.log(err);
    } else {
      //check if there is a user
      if (foundUser) {
        //check if the password of the user is the same as the password entered in the login page using bcrypt
        //i.e. compare the two hashed and salted passwords
        bcrypt.compare(password, foundUser.password, function(err, result) {
          if(result === true){
            //render the secrets page
            res.render("secrets");
          }
        });

      }
    }
  });
});*/

//////////////////////////////////////////USING BCRYPT////////////////////////////////////

app.listen(3000, function(){
  console.log("Server started on port 3000!");
});
