const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL_PROD,  // siempre usar base remota
  ssl: {
    rejectUnauthorized: false, // necesario para conexión segura con Render
  },
});

module.exports = pool;
