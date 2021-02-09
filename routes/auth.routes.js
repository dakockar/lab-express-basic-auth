const router = require("express").Router();
const bcrypt = require('bcryptjs');
const UserModel = require("../models/User.model.js")

router.get("/signup", (req, res, next) => {
    res.render("auth/signup.hbs");
})

router.post("/signup", (req, res, next) => {
    const { username, password } = req.body;

    // empty check
    if (!username || !password) {
        res.render("auth/signup.hbs", { msg: "Please fill in all the fields!" });
        return;
    }

    UserModel.findOne({ username })
        .then((result) => {
            if (!result) {
                // hashing the password
                let salt = bcrypt.genSaltSync(10);
                let hash = bcrypt.hashSync(password, salt);

                // inserting the username and the password to the database
                UserModel.create({ username, password: hash })
                    .then(() => {
                        res.redirect("/");
                    })
                    .catch((err) => {
                        console.log("There was a problem with the signup. ", err)
                    });
            }
            else {
                res.render("auth/signup.hbs", { msg: "This username is already in use!" });
                return;
            }
        })
        .catch((err) => {
            next(err);
        });

})


router.get("/login", (req, res, next) => {

    // redirects the user to the profile page if a user is logged in
    if (req.session.loggedInUser) {
        res.redirect("/profile");
    }
    else {
        res.render("auth/login.hbs");
    }
})

router.post("/login", (req, res, next) => {
    const { username, password } = req.body;

    if (!username || !password) {
        res.render("auth/login.hbs", { msg: "Please fill in all the fields!" });
        return;
    }

    // using Sync method
    UserModel.findOne({ username })
        .then((result) => {
            if (result) {
                let isMatched = bcrypt.compareSync(password, result.password);
                if (isMatched) {
                    req.session.loggedInUser = result;

                    res.redirect("/profile");
                }
                else {
                    res.render("auth/login.hbs", { msg: "Incorrect password" });
                }
            }
            else {
                res.render("auth/login.hbs", { msg: "No such user!" });
            }
        })
        .catch((err) => {
            next(err);
        });



    // using Async method

    // UserModel.findOne({ username })
    //     .then((result) => {
    //         if (result) {
    //             // console.log(result);
    //             bcrypt.compare(password, result.password)   // this returns true or false
    //                 .then((isMatched) => {
    //                     if (isMatched) {
    //                         req.session.loggedInUser = result;

    //                         res.redirect("/profile");
    //                     }
    //                     else {
    //                         res.render("auth/login.hbs", { msg: "Incorrect password" });
    //                     }
    //                 })
    //                 .catch((err) => {
    //                      next(err);
    //                 });
    //         }
    //         else {
    //             res.render("auth/login.hbs", { msg: "No such user!" })
    //         }
    //     })
    //     .catch((err) => {
    //         next(err);
    //     });

})

function checkLoggedInUser(req, res, next) {
    if (req.session.loggedInUser) {
        console.log("user is logged in");
        next();
    }
    else {
        console.log("you must login first")
        res.redirect("/login");
    }
}

router.get("/profile", checkLoggedInUser, (req, res) => {
    let username = req.session.loggedInUser.username;
    res.render("profile.hbs", { username });
})

router.get("/main", checkLoggedInUser, (req, res) => {
    res.render("main.hbs");
})

router.get("/private", checkLoggedInUser, (req, res) => {
    res.render("private.hbs");
})


module.exports = router;