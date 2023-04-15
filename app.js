require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const app = express();
const port = process.env.PORT || 3000;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.COOKIE_SECRET_KEY,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.set("strictQuery", true);
mongoose.connect(process.env.DB_CONNECTION);

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
  },
  lastName: {
    type: String,
  },
  email: {
    type: String,
  },
  googleId: String,
});
const options = {
  usernameField: "email",
  errorMessages: {
    UserExistsError: "The email given is already registered",
  },
};

userSchema.plugin(passportLocalMongoose, options);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("user", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    cb(null, { id: user.id, username: user.username });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: process.env.CALLBACK_URL,
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get("/", function (req, res) {
  res.render("home");
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/Security",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect secure.
    res.redirect("/Security");
  }
);

app.get("/signup", function (req, res) {
  res.render("signup");
});

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/Security", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("Security");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      res.render("Security", { err });
    } else {
      res.redirect("/");
    }
  });
});

app.get("/about", function (req, res) {
  res.render("about");
});

app.get("/about/privacypolicy", function (req, res) {
  res.render("privacypolicy");
});

app.post("/signup", function (req, res) {
  const firstName = req.body.firstName;
  const lastName = req.body.lastName;
  const email = req.body.email;
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword;

  const re = /(?=.*\d)(?=.*[A-Z])(?=.*[a-z])/;
  const em = /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/;
  const le = /^[a-zA-Z]+$/;

  if (!re.test(password)) {
    const err =
      "The password entered must contain atleast one uppercase, lowercase and number";
    res.render("signup", { err });
  } else if (!em.test(email)) {
    const err = "Please enter a valid email address";
    res.render("signup", { err });
  } else if (!le.test(firstName) || !le.test(lastName)) {
    const err = "Name must contain only letters";
    res.render("signup", { err });
  } else if (password.length < 6) {
    const err = "Password must be atleast 6 characters long";
    res.render("signup", { err });
  } else if (password != confirmPassword) {
    const err = "password mismatch";
    res.render("signup", { err });
  } else {
    User.register(
      { email: email, firstName: firstName, lastName: lastName },
      password,
      function (err, user) {
        if (err) {
          res.render("signup", { err });
        } else {
          passport.authenticate("local")(req, res, function () {
            res.redirect("/Security");
          });
        }
      }
    );
  }
});

app.post("/login", function (req, res) {
  const user = new User({
    email: req.body.email,
    password: req.body.password,
  });

  req.login(user, function (err) {
    if (err) {
      res.render("login", { err });
    } else {
      passport.authenticate("local", function (err, user) {
        if (err) {
          res.redirect("/login");
        } else if (user == false) {
          err = "Email or password incorrect";
          res.render("login", { err });
        } else {
          res.redirect("/Security");
        }
      })(req, res);
    }
  });
});

app.listen(port, function (req, res) {
  console.log("Server has started successfully");
});
