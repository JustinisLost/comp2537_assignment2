require('./utils.js');
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;
const bcrypt = require('bcrypt');
const Joi = require('joi');

const app = express();

const saltRounds = 12;
const PORT = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000; // 1 hour

/* Secrets */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const { database } = include('databaseConnection');
const userCollection = database.db(mongodb_database).collection('users');


app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(__dirname + "/public"));

app.set('view engine', 'ejs');


const mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
    cookie: {
        maxAge: expireTime
    }
}));

/* Middleware */

function isValidSession(req) {
    return req.session.authenticated;
}

function sessionValidation(req, res, next) {
    if (isValidSession(req)) {
        next();
    } else {
        res.redirect('/login');
    }
}

function adminAuthorization(req, res, next) {
    if (req.session.user_type === 'admin') {
        next();
    } else {
        res.status(403);
        res.render('index', {
            authenticated: false,
            message: "You are not authorized."
        });
    }
}

app.get('/', (req, res) => {

    res.render('index', {
        authenticated: req.session.authenticated,
        name: req.session.name,
        message: null
    });
});

app.post('/signup', async (req, res) => {

    const { name, email, password } = req.body;

    const schema = Joi.object({
        name: Joi.string().max(50).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(50).required()
    });

    const validation = schema.validate({ name, email, password });

    if (validation.error) {
        return res.render('index', {
            authenticated: false,
            message: validation.error.details[0].message
        });
    }

    const existingUser = await userCollection.findOne({ email });

    if (existingUser) {

        return res.render('index', {
            authenticated: false,
            message: "Email already exists."
        });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        name,
        email,
        password: hashedPassword,
        user_type: "user"
    });

    req.session.authenticated = true;
    req.session.name = name;
    req.session.email = email;
    req.session.user_type = "user";

    res.redirect('/dogs');
});

app.get('/login', (req, res) => {

    res.render('login', {
        message: null
    });
});

app.post('/login', async (req, res) => {

    const { email, password } = req.body;

    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(50).required()
    });

    const validation = schema.validate({ email, password });

    if (validation.error) {
        return res.render('login', {
            message: "Invalid input."
        });
    }

    const user = await userCollection.findOne({ email });

    if (!user) {
        return res.render('login', {
            message: "User and password not found."
        });
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
        return res.render('login', {
            message: "User and password not found."
        });
    }

    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.email = user.email;
    req.session.user_type = user.user_type;

    res.redirect('/dogs');
});

app.get('/dogs', sessionValidation, (req, res) => {

    res.render('dogs', {
        name: req.session.name
    });
});

app.get('/admin',
    sessionValidation,
    adminAuthorization,
    async (req, res) => {

        const users = await userCollection.find({}).toArray();

        res.render('admin', {
            users
        });
});

app.get('/promote/:email',
    sessionValidation,
    adminAuthorization,
    async (req, res) => {

        const email = req.params.email;

        await userCollection.updateOne(
            { email: email },
            { $set: { user_type: 'admin' } }
        );

        res.redirect('/admin');
});

app.get('/demote/:email',
    sessionValidation,
    adminAuthorization,
    async (req, res) => {

        const email = req.params.email;

        await userCollection.updateOne(
            { email: email },
            { $set: { user_type: 'user' } }
        );

        res.redirect('/admin');
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.use((req, res) => {
    res.status(404);
    res.render('404');
});

app.listen(PORT, () => {
    console.log("Node application listening on port " + PORT);
});