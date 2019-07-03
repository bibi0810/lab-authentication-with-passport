const express = require("express");
const bcrypt = require("bcrypt");
const passportRouter = express.Router();
const User = require("../models/user");
const passport = require("passport");
const ensureLogin = require("connect-ensure-login");

passportRouter.get("/signup", (req, res) => {
  res.render("passport/signup");
});

passportRouter.get("/login", (req, res) => {
  res.render("passport/login", { errorMessage: req.flash("error") });
});

passportRouter.get(
  "/private-page",
  ensureLogin.ensureLoggedIn(),
  (req, res) => {
    res.render("passport/private", { user: req.user });
  }
);

passportRouter.post(
  "/passport/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/passport/login",
    failureFlash: true
  })
);

passportRouter.post("/signup", (req, res) => {
  const { username, password } = req.body;

  if (!password || !username) {
    res.render("passport/signup", { errorMessage: "Both fields are required" });

    return;
  } else if (password.length < 8) {
    res.render("passport/signup", {
      errorMessage: "Password needs to be 8 characters min"
    });

    return;
  }
  User.findOne({ username: username })
    .then(user => {
      if (user) {
        res.render("passport/signup", {
          errorMessage: "This username is already taken"
        });

        return;
      }
      const salt = bcrypt.genSaltSync();
      const hash = bcrypt.hashSync(password, salt);

      return User.create({
        username,
        password: hash
      }).then(data => {
        res.redirect("/");
      });
    })
    .catch(err => {
      res.render("passport/signup", { errorMessage: err._message });
    });
});
passportRouter.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

module.exports = passportRouter;
