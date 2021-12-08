const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const passport = require("passport")

const users = require("./routes/api/users")
const app = express();

// parses the HTTP request body
// Bodyparser middleware
app.use(
    bodyParser.urlencoded({
    extended: false
    })
  );

app.use(bodyParser.json());

// DB Config
const uri = require("./config/keys").mongoURI;

mongoose.connect(uri ,{ useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("database connected") )
    .catch(err => console.log(err));

// Passport middleware
app.use(passport.initialize());
// Passport config
require("./config/passport")(passport);
// Routes
app.use("/api/users", users);

const port = process.env.PORT || 5000; // process.env.port is Heroku's port if you choose to deploy the app there

app.listen(port, () => console.log(`Server up and running on port ${port} !`));