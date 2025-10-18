const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL_PROD,  // siempre usar base remota
  ssl: {
    rejectUnauthorized: false, // necesario para conexión segura con Render
  },
  max: 3 // Limita el pool a 3 conexiones simultáneas (ajusta según tu plan de Render)
});

module.exports = pool;
