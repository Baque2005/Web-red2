const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const pool = require('../config/db');

const isDev = process.env.NODE_ENV === 'development';
const CALLBACK_URL = isDev
  ? process.env.GOOGLE_CALLBACK_URL_DEV
  : process.env.GOOGLE_CALLBACK_URL_PROD;

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: CALLBACK_URL,
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // Obtiene los datos del perfil de Google
    const email = profile.emails[0].value;
    const photo = profile.photos[0].value;
    const name = profile.displayName;

    // Busca si el usuario ya existe
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    let user;

    if (rows.length > 0) {
      user = rows[0]; // Usuario ya existe
    } else {
      // Crea un nuevo usuario si no existe
      const insert = await pool.query(
        'INSERT INTO users (name, email, photo, rol) VALUES ($1, $2, $3, $4) RETURNING *',
        [name, email, photo, 'miembro']
      );
      user = insert.rows[0];
    }

    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));

// Serializa el usuario usando su ID interno (no el google_id)
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserializa el usuario buscando por ID interno en la base de datos
passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    done(null, rows[0] || null);
  } catch (err) {
    done(err, null);
  }
});
