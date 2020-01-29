const bcrypt = require('bcryptjs');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const session = require("express-session"); // install
const KnexSessionStore = require("connect-session-knex")(session);

const dbConnection = require("../data/dbConfig.js");

const Users = require('../data/users/users-model.js');
const server = express();

const sessionConfig = {
    name: "cookieMonster",
    // secret is used for cookie encryption
    secret: process.env.SESSION_SECRET || "keep it secret, keep it safe!",
    cookie: {
        maxAge: 1000 * 60 * 10, // 10 minutes in ms
        secure: false, // set to true in production, only send cookies over HTTPS
        httpOnly: true, // JS cannot access the cookies on the browser
    },
    resave: false,
    saveUninitialized: true, // read about it for GDPR compliance
    store: new KnexSessionStore({
        knex: dbConnection,
        tablename: "sessions",
        sidfieldname: "sid",
        createtable: true,
        clearInterval: 60000,
    }),
};


server.use(helmet());
server.use(session(sessionConfig)); // turn on sessions

server.use(express.json());
server.use(cors());

server.get('/', (req,res)=> {
    res.send('Server is up and running!')
})



server.post('/api/register', (req, res) => {
    let user = req.body;

    const hash = bcrypt.hashSync(req.body.password, 8);

    user.password = hash;

    Users.add(user)
      .then(saved => {
        res.status(201).json(saved);
      })
      .catch(err => {
        res.status(500).json(err);
      });
  });

server.post('/api/login', (req,res) => {
    let { username, password } = req.body;
    
    Users.findBy({ username })
    .first()
    .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
            req.session.loggedIn = true; // used in restricted middleware
            req.session.userId = user.id; // in case we need the user id later

            res.status(200).json({
                message: `Welcome ${user.username}!`,
            });
        } else {
            res.status(401).json({ message: "Invalid Credentials" });
        }
    })
    .catch(error => {
        res.status(500).json(error);
    });
});

server.get("/logout", (req, res) => {
    if (req.session) {
        req.session.destroy(err => {
            if (err) {
                res.status(500).json({
                    you:
                        "can checkout any time you like, but you can never leave!",
                });
            } else {
                res.status(200).json({ bye: "thanks for playing" });
            }
        });
    } else {
        res.status(204);
    }
});


// function restrict(req, res,next) {
//     const { username, password } = req.headers;

//     if (username && password) {
//         Users.findBy({ username })
//             .first()
//             .then(user => {
//                 if (user && bcrypt.compareSync(password, user.password)) {
//                     next();
//                 } else {
//                     res.status(401).json({message: 'Invalid Credentials' });
//                 }
//             })
//             .catch(err => {
//                 res.status(500).json({error: 'Server Error'})
//             });
//     } else {
//         res.status(400).json({ error: 'No credentials provided' });
//     }
// }

function restrict(req, res,next) {
    if (req.session && req.session.loggedIn) {
        next();
    } else {
        res.status(401).json({ you: "shall not pass!" });
    }
    }


server.get('/api/user',restrict, (req,res) => {
    Users.find()
        .then(users => {
            res.json(users)
        })
        .catch(err => {
            res.send(err)
        })
});

module.exports = server;