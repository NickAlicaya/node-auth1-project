const knex = require('knex');

const configuration = require('../knexfile.js');

const environment = process.env.NODE_ENV || "development";

const db = knex(configuration.development);

module.exports = db; 

