 require("dotenv").config();
const express = require("express");
const bodyparser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const { connected } = require("process");
const encrypt = require("mongoose-encryption"); // mongooseencryption
const md5 = require("md5"); // hasing the password
const bcrypt = require("bcrypt");
const saltRounds = 10;
const session = require("express-session");
const passportlocal = require("passport-local");
const passportLocalMongoose = require("passport-local-mongoose");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const nodemailer = require("nodemailer");
const flash = require("connect-flash");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyparser.urlencoded({ extended: true }));
app.use(flash());

//this will set our express-session || for cookie
app.use(
  session({
    secret: "keyboardcatdogcst",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

const password = process.env.MONGOOSE_ALTAS_PASSWORD;
mongoose
  .connect(
    "mongodb+srv://mahanthasimha37:" +
      password +
      "@mahanthasimha.0g62iuc.mongodb.net/user"
  )
  .then(() => console.log("Connected!"));

const userSchema = new mongoose.Schema({
  //here we are creating new Manja structure
  name: String,
  password: String,
  googleId: String,
  secret: [String],
});

userSchema.plugin(passportLocalMongoose); //this will add salting and hashing to the code
userSchema.plugin(findOrCreate); //this is for the pakage findorcreate
// userSchema.plugin(findOrCreate);

// user.plugin(encrypt, { secret: process.env.SECRET ,encryptedFields: ['password'] });this will encrypt the password

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
  //this for the passportLocalMongoose
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  //this for the passportLocalMongoose
  User.findById(id)
    .exec()
    .then((user) => {
      done(null, user);
    })
    .catch((err) => {
      done(err, null);
    });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      // console.log(profile) i can see all the information about the person
      User.findOrCreate(
        { googleId: profile.id, username: profile.displayName },
        function (err, user) {
          //findorcreate is not a mongoose thing ,we need  install findorcreate pakeage from npm
          return cb(err, user);
        }
      );
    }
  )
);

app.get("/", (req, res) => {
  res.render("home");
  // res.send('<script>alert("This is an alert message");</script>');
});

app.get("/register", (req, res) => {
  res.render("register");
});
app.get(
  "/auth/google", // This path came from the login.EJS file on line number 31.
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets", // this is a callback function given by the Google which we are redirecting to the secret page
  passport.authenticate("google", { failureRedirect: "/login " }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/logout", (req, res) => {
  res.redirect("/");
});

app.get("/passcode", (req, res) => {
  res.render("passcode");
});

app.use("/forgotpassword", async (req, res) => {
  try {
    const username = await User.findOne({ username: req.body.username });
    if (!username) {
      const errorMessage = "User doesn't exist";
      return res.render("passcode", { data: errorMessage });
    }

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    const num = Math.floor(1000 + Math.random() * 9000).toString(); // Generate a 4-digit random number

    const mailOptions = {
      from: process.env.EMAIL,
      to: req.body.username, // Use retrieved email address
      subject: "Password Reset Code",
      text: `Your password reset code is: ${num}`,
    };

    const info = await transporter.sendMail(mailOptions);
    if (info) {
      console.log("Email sent: " + info.response);
      numm.push(num); // Assuming numm is used elsewhere for verification
      res.redirect(
        `/checkpass?username=${encodeURIComponent(req.body.username)}`
      );
    } else {
      console.error("Error sending email:", info.error);
      res.status(500).send("Failed to send password reset code");
    }
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/checkpass", (req, res) => {
  const { username } = req.query;
  console.log(`Received data - username: ${username}`);
  res.render("checkpass", { username }); // Pass username to the EJS template
  const number = numm.length - 1;
  console.log(numm[number]);
});

numm = []; //shared memory block

app.post("/checkpass", async (req, res) => {
  const { username, otp, newpass, renewpass } = req.body;

  console.log("Username:", username);
  console.log("OTP from numm[0]:", numm[0], "OTP from request:", otp);
  console.log("New Password:", newpass, "Retyped New Password:", renewpass);
  const otpnum = numm[numm.length - 1];
  console.log(otpnum);

  try {
    // Find the user by username
    const user = await User.findOne({ username });

    

    // Verify the OTP
    if (otpnum !== otp) {
      console.log("Invalid OTP");
      numm = [];
      return res.render("passcode", { dataotp: "your otp is wrong Re-send the OTP" });
    }

    // Check if the new passwords match
    if (newpass !== renewpass) {
      console.log("Passwords do not match");
      return res.render("passcode", { datap: "your password dosnot match Re-send the otp" });
    }

    // Set the new password using passport-local-mongoose
    user.setPassword(newpass, async (err) => {
      if (err) {
        console.error("Error setting new password:", err);
        return res.render("checkpass", {
          data: "An error occurred while updating the password",
        });
      }

      // Save the updated user document
      await user.save();
      numm = [];
      console.log("Updated Document:", user);
      return res.render("login", { datasus: "Password has changed successfully" });
    });
  } catch (error) {
    console.error("Error updating user:", error);
    if (!res.headersSent) {
      return res.render("checkpass", {
        data: "An error occurred while updating the password",
      });
    }
  }
});



app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      console.log(req.user.id);
      const documentId = req.user.id;
      const document = await User.findById(documentId).exec();
      console.log(document);
      res.render("secrets", { usersWithSecrets: document });
    } catch (err) {
      console.error(err);
      // Handle error
      res.status(500).send("Internal Server Error");
    }
  } else {
    // Handle unauthenticated access
    res.redirect("/login");
  }

  // User.find({ "secret": { $ne: null } })
  //     .exec()
  //     .then(foundUsers => {
  //         if (foundUsers) {
  //             res.render("secrets",{ usersWithSecrets: foundUsers });//this will add all the data to database and also display it
  //         }
  //     })
  //     .catch(err => {
  //         console.log(err);
  //     });
});
app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    //if  the secret page is authenticated We can open the secret page directly
    res.render("submit"); // and isauthenticated function is A function from passport.JS
  } else {
    res.redirect("/login");
  }
});
app.post("/submit", (req, res) => {
  const usersecret = req.body.secret;

  if (req.isAuthenticated()) {
    // User is authenticated, proceed with updating the secrets
    User.findById(req.user.id)
      .then((foundUser) => {
        if (foundUser) {
          //    foundUser.secret=usersecret;
          foundUser.secret = foundUser.secret || [];
          foundUser.secret.push(usersecret);
          foundUser
            .save()
            .then(() => {
              res.redirect("/secrets");
            })
            .catch((error) => {
              console.error(error);
            });
        } else {
          throw new Error("User not found");
        }
      })
      .catch((error) => {
        console.error(error);
      });
  } else {
    // User is not authenticated, redirect to login or handle it accordingly
    res.redirect("/login");
  }
});

app.post("/register", (req, res) => {
  const username = req.body.username;
  const newUser = new User({ username: username });

  console.log(username);
  User.register(newUser, req.body.password, function (err, user) {
    //from passport
    if (err) {
      console.log(err);
      const errorMessage = "User already exist";
      return res.render("register", { data: errorMessage });
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", function (req, res, next) {
  // Use passport.authenticate to handle the login attempt
  passport.authenticate("local", function (err, user, info) {
    if (err) {
      return next(err); // If there's an error, pass it to the next middleware
    }
    if (!user) {
      // If authentication fails, render the login page with a custom error message
      const errorMessage = "The username or passcode is incorrect";
      return res.render("login", { data: errorMessage });
    }
    // If authentication succeeds, log in the user
    req.login(user, function (err) {
      if (err) {
        return next(err);
      }
      // Redirect to the secrets page after successful login
      return res.redirect("/secrets");
    });
  })(req, res, next); // Invoke the function with req, res, and next
});




app.listen(3000, function () {
  console.log("your server is stated on port 3000");
});



























// app.post("/login", (req, res) => {
//     const user = new User({
//         name: req.body.username,
//         password: req.body.password
//     })
//     req.login(user, function(err){
//         if (err) {
//             console.log(err)
//         }
//         else {
//             passport.authenticate("local")(req, res, function () {
//                 res.redirect("/secrets");
//             })
//         }
//     })

// })

//passport
//passport-local
//passport-local-mongoose
//express-session

//if we don't use cookies in our web app we can use this this hashing and salting
// app.post("/login", (req, res) => {
//     const username = req.body.username
//     const password = (req.body.password)
//     console.log(username);
//     console.log(password);

//     User.findOne({ name: username })
//         .then((docs) => {
//             bcrypt.compare(password, docs.password, function (err, result) {
//                 //this is getting both the password from the your and it will check the hash+slat password in the database and it will compair it
//                 if (result == true) res.render("secrets");
//                 else {
//                     res.send("incorrect password")
//                 }
//             });

//         })
//         .catch((err) => {
//             console.log(err);
//         });

// })

// app.post("/register", (req, res) => {

//     console.log(req.body.username);
//     console.log(req.body.password);
//     bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
//         // Store hash in your password DB.
//         const data1 = new User({
//             name: req.body.username,
//             password: hash
//         });
//         User.findOne({ name: req.body.username })
//             .then((docs) => {
//                 if (docs && docs.name === req.body.username) {
//                     res.send("user ane is already exist")
//                 }
//                 else {
//                     data1.save().then(() => {
//                         res.render("secrets")
//                     });
//                 }
//             })
//             .catch((err) => {
//                 console.log(err);
//             });

//     });

// });
