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
    const googleId = profile.id;
    const email = profile.emails[0].value;
    const photo = profile.photos[0].value;
    const name = profile.displayName;

    // Busca si el usuario ya existe por google_id
    let { rows } = await pool.query('SELECT * FROM users WHERE google_id = $1', [googleId]);
    let user;

    if (rows.length > 0) {
      user = rows[0];
      // SOLUCIÓN: Si el email es el tuyo y modalidad no es 'vip', actualiza a vip
      if (email === "baqueperez89@gmail.com" && user.modalidad !== "vip") {
        const update = await pool.query(
          'UPDATE users SET modalidad = $1 WHERE id = $2 RETURNING *',
          ["vip", user.id]
        );
        user = update.rows[0];
      }
    } else {
      // Si no existe, verifica si hay un usuario con el mismo email (migración de cuentas antiguas)
      const existing = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      if (existing.rows.length > 0) {
        // Actualiza ese usuario para agregarle el google_id
        const update = await pool.query(
          'UPDATE users SET google_id = $1, photo = $2 WHERE id = $3 RETURNING *',
          [googleId, photo, existing.rows[0].id]
        );
        user = update.rows[0];
      } else {
        // Crea un nuevo usuario con google_id y modalidad
        // Si el email es el tuyo, modalidad vip, si no, gratuita
        const modalidadDefault = email === "baqueperez89@gmail.com" ? "vip" : "gratuita";
        const insert = await pool.query(
          'INSERT INTO users (google_id, name, email, photo, rol, modalidad) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
          [googleId, name, email, photo, 'miembro', modalidadDefault]
        );
        user = insert.rows[0];
      }
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
