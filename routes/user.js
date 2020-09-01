const express = require('express');
const bcrypt = require('bcryptjs');
const { check, validationResult } = require('express-validator')

const db = require('../db/models');
const {csrfProtection, asyncHandler} = require('./utils');

const router = express();
const userValidators = [
    check('firstName')
        .exists({checkFalsy: true})
        .withMessage('Please provide value for First Name')
        .isLength({max:50})
        .withMessage('First Name must not be longer than 50 characters long'),
    check('lastName')
        .exists({checkFalsy: true})
        .withMessage('Please provide value for Last Name')
        .isLength({max:50})
        .withMessage('Last Name must not be longer than 50 characters long'),
    check('emailAddress')
        .exists({checkFalsy: true})
        .withMessage('Please provide value for Email Address')
        .isLength({max:255})
        .withMessage('Email Address must not be longer than 255 characters long')
        .isEmail()
        .withMessage('Must be a valid Email Address')
        .custom( (value) => {
            return db.User.findOne({
                where: {
                    emailAddress: value
                }
            })
            .then((user) => {
                if (user) {
                    return Promise.reject('The provided email address is already in use by another account')
                }
            })
        }),
    check('password')
        .exists({checkFalsy: true})
        .withMessage('Please provide value for Password')
        .isLength({max:50})
        .withMessage('Password must not be longer than 50 characters')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])/, 'g')
        .withMessage('Password must contain at least one lowercase letter, uppercase letter, number, and special character'),
    check('confirmPassword')
        .exists({checkFalsy: true})
        .withMessage('Please provide value for Confirm Password')
        .isLength({max:50})
        .withMessage('Confirm Password must not be longer than 50 characters')
        .custom( (value, {req}) => {
            if (value !== req.body.password) throw new Error('Confirm Password does not match Password');
            return true;
        })
];

const loginValidators = [
    check('emailAddress')
        .exists({checkFalsy: true})
        .withMessage("Please provide a value for Email Address"),
    check('password')
        .exists({checkFalsy: true})
        .withMessage("Please provide a value for Password")
];

router.get('/user/register', csrfProtection, (req, res) => {
    const user = db.User.build();

    res.render('user-register', {
        user,
        title: 'Register',
        csrfToken: req.csrfToken(),
    })
});


router.post('/user/register', csrfProtection, userValidators, asyncHandler( async (req, res) => {
    const {
        emailAddress,
        firstName,
        lastName,
        password
    } = req.body;

    const user = db.User.build({
        emailAddress,
        firstName,
        lastName
    })

    const validatorErrors = validationResult(req);

    if (validatorErrors.isEmpty()) {
        const hashedPassword = await bcrypt.hash(password, 10);
        user.hashedPassword = hashedPassword;
        await user.save();
        res.redirect('/');
    } else {
        const errors = validatorErrors.array().map((error) => error.msg);
        res.render('user-register', {
            title: 'Register',
            user,
            errors,
            csrfToken: req.csrfToken()
        })
    }
}));

router.get('/user/login', csrfProtection, (req, res) => {
    res.render('user-login', {
        title: "Login",
        csrfToken: req.csrfToken()
    })
});

router.post('/user/login', csrfProtection, loginValidators, asyncHandler( async (req, res) => {
    const {
        emailAddress,
        password
    } = req.body;

    const errors = [];
    const validatorErrors = validationResult(req);

    if (validatorErrors.isEmpty()) {
        const user = await db.User.findOne({
            where: {
                emailAddress
            }
        })
        if (user) {
            const passwordMatch = bcrypt.compare(password, user.hashedPassword.toString());
            if (passwordMatch) {
                // todo login user
                return res.redirect('/');
            }
        }
        errors.push('Login failed for the provided email address and password')
    }
    errors.push(...validatorErrors.array().map((error) => error.msg))

    res.render('user-login', {
        title: 'Login',
        emailAddress,
        errors,
        csrfToken: req.csrfToken()
    })
}));


module.exports = router;
