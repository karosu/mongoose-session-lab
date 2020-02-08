const { Router } = require('express');
const router = new Router();
const User = require('../models/User.model');
const bcryptjs = require('bcryptjs');
const saltRounds = 10;
const mongoose = require('mongoose');

const routeGuard = require('../configs/route-guard.config');


// .get() route ==> to display the signup form to users

router.get('/signup', (req, res) => res.render('auth/signup'));
router.get('/login', (req, res) => res.render('auth/login'));



// .post() route ==> to process form data
// routes/auth.routes.js
// ... the setup and the get route



//SIGNUP POST
router.post('/signup', (req, res, next) => {
  const { username, email, password} = req.body;

  bcryptjs
    .genSalt(saltRounds)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashedPassword => {
      console.log(`Password hash: ${hashedPassword}`);
      User.findOne({username})
      .then(user => {
        if (user !== null) {
          res.render('auth/signup', {
            errorMessage: "Username Already Exist"
          })
          return
        }
        User.create({username, passwordHash: hashedPassword, email})
        .then(() => {
          res.redirect('/');
        })
        .catch(error => next(error));
      })    })
    .catch(error => next(error));
});


//LOGIN POST

router.post("/login", (req, res, next) => {
  const theUsername = req.body.username;
  const thePassword = req.body.password;

  if (theUsername === "" || thePassword === "") {
    res.render("auth/login", {
      errorMessage: "Please enter both, username and password to sign up."
    });
    return;
  }

  User.findOne({ "username": theUsername })
  .then(user => {
      if (!user) {
        res.render("auth/login", {
          errorMessage: "The username doesn't exist."
        });
        return;
      }
      if (bcryptjs.compareSync(thePassword, user.passwordHash)) {
        // Save the login in the session!
        req.session.currentUser = theUsername;
        res.redirect("/");
      } else {
        res.render("auth/login", {
          errorMessage: "Incorrect password"
        });
      }
  })
  .catch(error => {
    next(error);
  })
});

router.post('/logout', routeGuard, (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

module.exports = router;