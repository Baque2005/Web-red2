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
  (req, res, next) => {
    passport.authenticate('google', {
      failureRedirect: '/login/failed',
      session: true,
    }, (err, user, info) => {
      if (err) {
        console.error('❌ Error en Google callback:', err);
        return res.status(500).json({ success: false, message: 'Error en Google callback', error: err });
      }
      if (!user) {
        console.error('❌ Usuario no autenticado en Google callback:', info);
        return res.redirect('/login/failed');
      }
      req.logIn(user, (err) => {
        if (err) {
          console.error('❌ Error en req.logIn:', err);
          return res.status(500).json({ success: false, message: 'Error en req.logIn', error: err });
        }
        console.log('✅ Google callback - usuario autenticado:', user);
        console.log('✅ Google callback - session:', req.session);
        return res.redirect(CLIENT_URL);
      });
    })(req, res, next);
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
  console.log('--- /auth/login/success ---');
  console.log('Cookies:', req.headers.cookie);
  console.log('Session:', req.session);
  console.log('User:', req.user);
  console.log('isAuthenticated:', req.isAuthenticated && req.isAuthenticated());

  if (req.isAuthenticated && req.isAuthenticated()) {
    res.status(200).json({
      success: true,
      message: 'Autenticado con éxito',
      user: req.user,
      session: req.session,
      cookies: req.headers.cookie || null,
    });
  } else {
    res.status(401).json({
      success: false,
      message: 'No autenticado',
      user: null,
      session: req.session,
      cookies: req.headers.cookie || null,
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
