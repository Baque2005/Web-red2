const express = require('express');
const passport = require('passport');
require('dotenv').config();

const router = express.Router();

const isDev = process.env.NODE_ENV === 'development';

const CLIENT_URL = isDev
  ? process.env.CLIENT_URL_DEV
  : process.env.CLIENT_URL_PROD;

// 👉 Ruta para iniciar sesión con Google
router.get('/google', passport.authenticate('google', {
  scope: ['profile', 'email'],
  prompt: 'select_account', // fuerza selección
}));

// 👉 Callback de Google
router.get('/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/login/failed',
    session: true,
  }),
  (req, res) => {
    // Redirige manualmente tras autenticación exitosa
    res.redirect(CLIENT_URL);
  }
);

// 👉 Ruta de logout
router.get('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    // Si la petición es AJAX (fetch), responde con JSON
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      return res.json({ success: true, message: 'Sesión cerrada correctamente.' });
    }
    // Si es navegación normal, redirige
    res.redirect(CLIENT_URL);
  });
});

// 👉 Ruta opcional para verificar sesión activa
router.get('/login/success', (req, res) => {
  if (req.user) {
    res.status(200).json({
      success: true,
      message: 'Autenticado con éxito',
      user: req.user,
    });
  } else {
    res.status(401).json({
      success: false,
      message: 'No autenticado',
    });
  }
});

// 👉 Ruta opcional para manejar fallo de login
router.get('/login/failed', (req, res) => {
  res.status(401).json({
    success: false,
    message: 'Falló la autenticación con Google',
  });
});

// 👉 Nueva ruta: obtener información del usuario autenticado
router.get('/user', (req, res) => {
  if (req.isAuthenticated()) {
    res.status(200).json({
      user: req.user,
    });
  } else {
    res.status(401).json({ message: 'No autenticado' });
  }
});

module.exports = router;
