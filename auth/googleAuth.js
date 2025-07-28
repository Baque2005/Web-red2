const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const pool = require('../config/db');
require('dotenv').config();

const isDev = process.env.NODE_ENV === 'development';

const callbackURL = isDev
  ? process.env.GOOGLE_CALLBACK_URL_DEV
  : process.env.GOOGLE_CALLBACK_URL_PROD;

passport.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL,
    scope: ['profile', 'email'],
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const { id: googleId, displayName, emails, photos } = profile;
      const email = emails?.[0]?.value || null;
      const photo = photos?.[0]?.value || null;

      // Buscar usuario existente por google_id
      const existingUser = await pool.query(
        'SELECT * FROM users WHERE google_id = $1',
        [googleId]
      );

      if (existingUser.rows.length > 0) {
        // Usuario ya existe, retornar usuario
        return done(null, existingUser.rows[0]);
      }

      // Si no existe, crear usuario nuevo
      const now = new Date();
      const insertQuery = `
        INSERT INTO users (google_id, name, email, photo, registered_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
      `;
      const values = [googleId, displayName, email, photo, now];

      const newUser = await pool.query(insertQuery, values);
      return done(null, newUser.rows[0]);
    } catch (err) {
      console.error('Error in GoogleStrategy:', err);
      return done(err, null);
    }
  }
));

// Serializar usuario con el ID interno único (no google_id)
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserializar usuario usando el ID interno
passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    done(null, result.rows[0] || null);
  } catch (err) {
    done(err, null);
  }
});

