const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
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
  passport.authenticate('google', { failureRedirect: '/login/failed', session: false }),
  (req, res) => {
    // Genera el JWT con los datos del usuario
    const token = jwt.sign(
      { id: req.user.id, name: req.user.name, email: req.user.email, photo: req.user.photo },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    // Redirige al frontend con el token en la URL (o responde con JSON si usas fetch)
    res.redirect(`${CLIENT_URL}/?token=${token}`);
    // Alternativa para SPA: res.json({ token });
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

// Ruta para verificar el JWT
router.get('/me', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ user: null });
  const token = auth.replace('Bearer ', '');
  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ user });
  } catch {
    res.status(401).json({ user: null });
  }
});

module.exports = router;
