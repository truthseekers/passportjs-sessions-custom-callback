const express = require("express");
const { v4: uuidv4 } = require("uuid");
const session = require("express-session");
const FileStore = require("session-file-store")(session);
const path = require("path");
const bodyParser = require("body-parser");
const localStrategy = require("passport-local").Strategy;
const passport = require("passport");
const fs = require("fs");
const bcrypt = require("bcrypt");
const users = require("./users.json");

const app = express();

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: false }));

app.use(
  session({
    genid: (req) => {
      console.log("1. in genid req.sessionID: ", req.sessionID);
      return uuidv4();
    },
    store: new FileStore(),
    secret: "a private key",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  console.log("in serialize user: ", user);
  done(null, user);
});

passport.deserializeUser((user, done) => {
  console.log("in deserialize user: ", user);
  done(null, user);
});

passport.use(
  "signup",
  new localStrategy(
    { usernameField: "email", passwordField: "password" },
    async (email, password, done) => {
      try {
        if (password.length <= 4 || !email) {
          done(null, false, {
            message: "Your credentials do not match our criteria..",
          });
        } else {
          const hashedPass = await bcrypt.hash(password, 10);
          let newUser = { email, password: hashedPass, id: uuidv4() };
          users.push(newUser);
          await fs.writeFile("users.json", JSON.stringify(users), (err) => {
            if (err) return done(err); // or throw err?;
            console.log("updated the fake database");
          });

          done(null, newUser, { message: "signed up msg" });
        }
      } catch (err) {
        return done(err);
      }
    }
  )
);

passport.use(
  "login",
  new localStrategy(
    { usernameField: "email", passwordField: "password" },
    async (email, password, done) => {
      console.log("login named.");
      // done(null, userObject, { message: "Optional success/fail message"});
      // done(err) // Application Error
      // done(null, false, {message: "Unauthorized login credentials!"}) // User input error when 2nd param is false

      try {
        if (email === "apperror") {
          throw new Error(
            "Oh no! The application crashed! We have reported the issue. You can change next(error) to next(error.message) to hide the stack trace"
          );
        }
        const user = users.find((user) => user.email === email);

        if (!user) {
          return done(null, false, { message: "User not found!" });
        }

        const passwordMatches = await bcrypt.compare(password, user.password);

        if (!passwordMatches) {
          return done(null, false, { message: "Invalid credentials" });
        }

        return done(null, user, { message: "Hey congrats you are logged in!" });
      } catch (error) {
        return done(error); // application error!
      }
    }
  )
);

app.get("/", (req, res) => {
  console.log("get / req.sessionID: ", req.sessionID);
  console.log("req.user: ", req.user);
  console.log("req.isAuthenticated: ", req.isAuthenticated());
  // console.log("req.session: ", req.session);
  res.send("get index route. /");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.get("/success", (req, res) => {
  console.log("req.query: ", req.query);
  console.log("req.isAuthenticated: ", req.isAuthenticated());

  res.send(`You're in! ${req.query.message}`);
});

app.get("/failed", (req, res) => {
  console.log(`failed! ${req.query?.message}`);

  res.send("FAILED");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secureroute", (req, res) => {
  if (req.isAuthenticated()) {
    res.send(`welcome to the top secret place ${req.user.email}`);
  } else {
    res.send("Must log in first. visit /login");
  }
});

app.post(
  "/login",
  function (req, res, next) {
    console.log("useless function");

    passport.authenticate("login", async (err, user, info) => {
      console.log("err: ", err);
      console.log("user: ", user);
      console.log("info: ", info);

      if (err) {
        return next(err);
      }

      if (!user) {
        return res.redirect(`/failed?message=${info.message}`);
      }

      req.login(user, async (error) => {
        return res.redirect(`success?message=${info.message}`);
      });
    })(req, res, next);
  },
  (req, res, next) => {
    res.send("Hello"); // able to add functions after the authenticate call now.
  }
);

app.post("/signup", (req, res, next) => {
  passport.authenticate("signup", (err, user, info) => {
    if (err) {
      return next(err);
    }

    if (!user) {
      return res.redirect(`failed?message=${info.message}`);
    }

    req.login(user, async (error) => {
      if (error) {
        return next(err);
      }
      return res.redirect(`/success?message=${info.message}`);
    });
  })(req, res, next);
});

app.listen(3000, () => {
  console.log("listening on port 3000");
});
