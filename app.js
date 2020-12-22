require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();


app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(express.static("public"));

//here we tell our app to use the session package and se it with some initial configurations
app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

//here we tell our app to use passport and initialize it, and aswell use password for dealing with the sessions.
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    secret: String
});

//Passport Local Mongoose is what we going to use to hash and salt the password and save in our local database
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
        passReqToCallback: true
    },
    function (request, accessToken, refreshToken, profile, done) {
        User.findOrCreate({
            googleId: profile.id
        }, function (err, user) {
            return done(err, user);
        });
    }
));

app.get("/", function (req, res) {
    res.render("home");
});

app.get("/auth/google", function (req, res) {
    passport.authenticate("google", {
        scope: ["profile"]
    });
});

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
})

app.get("/auth/google/secrets",
    passport.authenticate('google', {
        failureRedirect: '/login'
    }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
    });

app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/secrets", function (req, res) {
    // if (req.isAuthenticated()) {
    //     res.render("secrets");
    // } else {
    //     res.redirect("/login");
    // }
    // the commented out code above is to verify if the user is logged in, if not he will be redirected to login page to log in.

    if (req.isAuthenticated()) {
        User.find({
            "secret": {
                $ne: null
            }
        }, function (err, foundUser) {
            if (err) {
                console.log(err);
            } else {
                if (foundUser) {
                    res.render("secrets", {
                        usersWithSecrets: foundUser
                    });
                }
            }
        });
    } else {
        res.redirect("/login");
    }

});

app.get("/logout", function (req, res) {
    req.logout();
    res.redirect("/");
});

app.post("/submit", function (req, res) {
    const submittedSecret = req.body.secret;

    console.log(req.user);

    User.findById(req.user.id, function (err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(function () {
                    res.redirect("/secrets");
                });
            }
        }
    });
});

app.post("/register", function (req, res) {

    User.register({
        username: req.body.username
    }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            // this line authenticats the user using the password and username
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets")
            })
        }
    })


});

app.post("/login", function (req, res) {
    user = new User({
        username: req.body.username,
        password: req.body.password
    });

    // the login() method coems for the passport npm
    req.login(user, function (err) {
        if (err) {
            console.log(err);
        } else {
            // this line authenticats the user using the password and username
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets")
            });
        }
    });
});





app.listen(3000, function () {
    console.log("Server is Running at port 3000!");
});