require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");


const app = express();


app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());



//----------------------------------------------------------------------

mongoose.connect(process.env.MONGO_URI);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate)

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        cb(null, { id: user.id, username: user.username, name: user.name });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});



passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));


//----------------------------------------------------------------------

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate('google', { scope: ["profile"] })
);

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: "/login" }),
    function (req, res) {
        res.redirect("/secrets");
    });

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/secrets", (req, res) => {
    User.find({ "secret": { $ne: null } }, (err, foundUsers) => {
        if (err) {
            console.log(err)
        } else {
            if (foundUsers) {
                res.render("secrets", { usersWithSecrets: foundUsers })
            }
        }
    });
});

app.get("/logout", (req, res) => {
    req.logout(function (err) {
        if (err) { return next(err); }
        res.redirect('/');
    });
});

app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("login");
    };
});

app.post("/submit", (req, res) => {
    const submittedSecret = req.body.secret;
    User.findById(req.user.id, (err, user) => {
        if (!err) {
            if (user) {
                user.secret = submittedSecret;
                user.save(() => {
                    res.redirect("/secrets");
                });
            };
        } else {
            console.log(err);
        };
    });

});

app.post("/register", (req, res) => {
    User.register({ username: req.body.username }, req.body.password, (err, user) => {
        if (err) {
            console.log(err)
            res.redirect("/register")
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        };
    });
});

app.post("/login", (req, res) => {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err) => {
        if (err) {
            console.log(err)
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        };
    });
});


//----------------------------------------------------------------------


app.listen(process.env.PORT, () => { console.log(`Server running on port ${process.env.PORT}`) });