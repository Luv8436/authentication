const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const keys = require("../../config/keys");
// Load input validation
const validateRegisterInput = require("../../validation/register");
const validateLoginInput = require("../../validation/login");
// Load User model
const User = require("../../models/User");
const passport = require("passport");

router.post('/register' , (req , res) => {
    const {errors , isValid } = validateRegisterInput(req.body);
    if(!isValid){
        return res.status(400).json(errors);
    }

    User.findOne({email : req.body.email})
    .then(user => {
        if(user){
            return res.status(400).json({email : "Email already exists"})
        }
        const newUser = new User({
            email : req.body.email,
            name : req.body.name,
            password : req.body.password
        });

        // Hash password before saving in database
        bcrypt.genSalt(10, function(err, salt) {
            bcrypt.hash(req.body.password, salt, function(err, hash) {
                // Store hash in your password DB.
                if(err) throw err;
                newUser.password = hash;
                newUser.save()
                .then(user => res.json(user))
                .catch(err => console.log(err));
            });
        });
    })
})


router.post('/login' ,(req , res) => {
    const {errors , isValid} = validateLoginInput(req.body);

    if(!isValid){
        return res.status("400").json(errors);
    }

    const email = req.body.email;
    const password = req.body.password;
    User.findOne({email})
    .then(user => {
        if(!user){
            return res.status("400").json({emailNotFound : "Email Not Found"});
        }
        
        //check the password
        bcrypt.compare(password, user.password , function(err, result) {
            // result == true
            if(err){
                console.log(err);
                return res.status("400").json(err);
            }
            if(result==false){
                return res.status("400").json({IncorrectPassword : "Incorrect Password"});
            }else{
                const payload = {
                    name : user.name,
                    id : user.id,
                }

                // sign a token
                jwt.sign(payload , keys.secretOrKey , {
                    expiresIn : "1h"
                } , 
                (err , token ) => {
                    res.json({success : true,
                    token : "Bearer "+token })
                })

            }
        });

        
    })

})

module.exports = router;