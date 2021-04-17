//reuire the packages
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

const secret = "Thisisourlittlesecret"; //some long string
//encrypt using the secret string and mongoose-encryption package. encrypt only the password
//the password will be encrypted when you call save and decrypted when you call find
userSchema.plugin(encrypt, {secret: secret, encryptedFields: ["password"]}); //add this BEFORE creating the mongoose model

const User = new mongoose.model("User", userSchema);


app.get("/", function(req, res) {
  res.render("home");
});

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});


//post request to register page
app.post("/register", function(req, res) {
  //create a new user document
  const newUser = new User({
    email: req.body.username,
    password: req.body.password
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


//post request to login route
app.post("/login", function(req, res){
  const username = req.body.username;
  const password = req.body.password;

  User.findOne({email: username}, function(err, foundUser) {
    if (err){
      console.log(err);
    } else {
      //check if there is a user
      if (foundUser) {
        //check if the password of the user is the same as the password entered in the login page
        if(foundUser.password === password) {
          //render the secrets page
          res.render("secrets");
        }
      }
    }
  });
});


app.listen(3000, function(){
  console.log("Server started on port 3000!");
});
