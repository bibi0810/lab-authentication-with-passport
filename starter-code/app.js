require("dotenv").config();

const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const express = require("express");
const favicon = require("serve-favicon");
const hbs = require("hbs");
const mongoose = require("mongoose");
const logger = require("morgan");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const User = require("./models/user");
const flash = require("connect-flash");
const FacebookStrategy = require("passport-facebook").Strategy;

mongoose
  .connect("mongodb://localhost/starter-code", { useNewUrlParser: true })
  .then(x => {
    console.log(
      `Connected to Mongo! Database name: "${x.connections[0].name}"`
    );
  })
  .catch(err => {
    console.error("Error connecting to mongo", err);
  });

const app_name = require("./package.json").name;
const debug = require("debug")(
  `${app_name}:${path.basename(__filename).split(".")[0]}`
);

const app = express();
// Middleware Setup
app.use(logger("dev"));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    cookie: { maxAge: 24 * 60 * 60 },
    resave: false,
    saveUninitialized: false
  })
);
// Express View engine setup

app.use(
  require("node-sass-middleware")({
    src: path.join(__dirname, "public"),
    dest: path.join(__dirname, "public"),
    sourceMap: true
  })
);

app.use(flash());

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser((id, done) => {
  User.findById(id)
    .then(user => {
      done(null, user);
    })
    .catch(err => {
      done(err);
    });
});

passport.use(
  new LocalStrategy((username, password, done) => {
    User.findOne({ username: username })
      .then(user => {
        if (!user || !bcrypt.compareSync(password, user.password)) {
          return done(null, false, { message: "Invalid credentials" });
        }
        done(null, user);
      })
      .catch(err => {
        done(err);
      });
  })
);

// passport.use(new FacebookStrategy({
//   clientID:process.env.FACEBOOK_CLIENT_ID,
//   clientSecret:process.env.FACEBOOK_CLIENT_SECRET,
//   callbackURL: "http://localhost:3000/auth/facebook/callback"
// }, (accessToken, refreshToken, profile, done) =>{
//   User.findOne ({facebookId: profile.id}).then(user => {
//     if(user) return done(null, user)
//     return user.create ({facebookId: profile.id}).then(newUser => {return done(null,newUser) });
//   }).catch(err => {
//     done(err);
// });

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: "http://localhost:3000/auth/facebook/callback"
    },
    (accessToken, refreshToken, profile, done) => {
      User.findOne({ facebookId: profile.id })
        .then(user => {
          if (user) return done(null, user);
          User.create({ facebookId: profile.id }).then(newUser => {
            return done(null, newUser);
          });
        })
        .catch(err => {
          console.log(err);
        });
    }
  )
);

app.use(passport.initialize());
app.use(passport.session());

app.use(
  require("node-sass-middleware")({
    src: path.join(__dirname, "public"),
    dest: path.join(__dirname, "public"),
    sourceMap: true
  })
);

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "hbs");
app.use(express.static(path.join(__dirname, "public")));
app.use(favicon(path.join(__dirname, "public", "images", "favicon.ico")));

// default value for title local
app.locals.title = "Express - Generated with IronGenerator";

// Routes middleware goes here
const index = require("./routes/index");
app.use("/", index);
const passportRouter = require("./routes/passportRouter");
app.use("/", passportRouter);

module.exports = app;
