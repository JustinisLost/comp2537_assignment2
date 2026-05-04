require('./utils.js');
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;
const bcrypt = require('bcrypt');
const Joi = require('joi');
const mongoSanitize = require('express-mongo-sanitize');

const app = express();
const saltRounds = 12;
const PORT = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000; // 1 hour

/* Secret info */
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
    resave: false,
    cookie: { maxAge: expireTime }
}));


app.get('/', (req, res) => {
    if (req.session.authenticated) {
        res.send(`
            <h1>Hello, ${req.session.name}</h1>
            <a href="/members">Go to Members Area</a><br>
            <a href="/logout">Logout</a>
        `);
    } else {
        res.send(`
            <h1>Welcome!</h1>
            <a href="/signup">Sign Up</a><br>
            <a href="/login">Login</a>
        `);
    }
});


app.get('/signup', (req, res) => {
    res.send(`
        <h1>Sign Up</h1>
        <form method="POST" action="/signup">
            <input name="name" placeholder="Name"><br>
            <input name="email" placeholder="Email"><br>
            <input name="password" type="password" placeholder="Password"><br>
            <button>Sign Up</button>
        </form>
    `);
});

app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;

    const schema = Joi.object({
        name: Joi.string().max(50).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(50).required()
    });
    const existingUser = await userCollection.findOne({ email });

    if (existingUser) {
        return res.send(`
           <p>Email already exists</p>
            <a href="/signup">Try again</a>
        `);
    }

    const validation = schema.validate({ name, email, password });

    if (validation.error) {
        return res.send(`
            <p>Error: ${validation.error.details[0].message}</p>
            <a href="/signup">Try again</a>
        `);
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        name,
        email,
        password: hashedPassword
    });

    
    req.session.authenticated = true;
    req.session.name = name;
    req.session.email = email;

    res.redirect('/members');
});


app.get('/login', (req, res) => {
    res.send(`
        <h1>Login</h1>
        <form method="POST" action="/login">
            <input name="email" placeholder="Email"><br>
            <input name="password" type="password" placeholder="Password"><br>
            <button>Login</button>
        </form>
    `);
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(50).required()
    });

    const validation = schema.validate({ email, password });

    if (validation.error) {
        return res.send(`
            <p>Invalid input</p>
            <a href="/login">Try again</a>
        `);
    }

    const user = await userCollection.findOne({ email });

    if (!user) {
        return res.send(`
            <p>User and password not found</p>
            <a href="/login">Try again</a>
`);
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
        return res.send(`
            <p>User and password not found</p>
            <a href="/login">Try again</a>
        `);
    }

    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.email = user.email;

    res.redirect('/members');
});


app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect('/');
    }

    const images = ["img1.jpg", "img2.jpg", "img3.jpg"];
    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.send(`
        <h1>Hello, ${req.session.name}</h1>
        <a href="/logout">Logout</a><br><br>
        <img src="/${randomImage}" width="300">
    `);
});


app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});


app.use((req, res) => {
    res.status(404).send("<h1>404 - Page Not Found</h1>");
});


app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});