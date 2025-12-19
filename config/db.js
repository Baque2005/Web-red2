const { Pool } = require('pg');
require('dotenv').config();

const connectionString =
  process.env.DATABASE_URL_SUPABASE || process.env.DATABASE_URL_PROD;

const pool = new Pool({
  connectionString,
  ssl: {
    rejectUnauthorized: false, // requerido por proveedores gestionados (Render/Supabase)
  },
});

module.exports = pool;
