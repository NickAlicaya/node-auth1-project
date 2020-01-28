const bcrypt = require('bcryptjs');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

const Users = require('../data/users/users-model.js');
const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req,res)=> {
    res.send('Server is up and running!')
})

// server.get('/restricted', (req, res, next) => {
//     if (req.headers.authorization) {
//         bcrypt.hash(req.headers.authorization, 10, (err, hash) => {
//             // 2^10 is the number of rounds
//             if (err) {
//                 res.status(500).json({ oops: "it broke" });
//             } else {
//                 res.status(200).json({ hash });
//             }
//         });
//     } else {
//         res.status(400).json({ error: "missing header" });
//     }
// });




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
            res.status(201).json({message: `Welcome ${user.username}!` })
        } else {
          res.status(401).json({message: 'Invalid Credentials' });  
        }
    });
});

function restrict(req, res,next) {
    const { username, password } = req.headers;

    if (username && password) {
        Users.findBy({ username })
            .first()
            .then(user => {
                if (user && bcrypt.compareSync(password, user.password)) {
                    next();
                } else {
                    res.status(401).json({message: 'Invalid Credentials' });
                }
            })
            .catch(err => {
                res.status(500).json({error: 'Server Error'})
            });
    } else {
        res.status(400).json({ error: 'No credentials provided' });
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