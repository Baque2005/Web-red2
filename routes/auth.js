const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const router = express.Router();

const isDev = process.env.NODE_ENV === 'development';
const CLIENT_URL = isDev
  ? process.env.CLIENT_URL_DEV
  : process.env.CLIENT_URL_PROD;

// Función para crear access token (dura 15 minutos)
const generateAccessToken = (user) => {
  return jwt.sign(
    { id: user.id, name: user.name, email: user.email, photo: user.photo },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
  );
};

// Función para crear refresh token (dura 7 días)
const generateRefreshToken = (user) => {
  return jwt.sign(
    { id: user.id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );
};

// Ruta para iniciar sesión con Google
router.get('/google', passport.authenticate('google', {
  scope: ['profile', 'email'],
  prompt: 'select_account',
}));

// Callback de Google - envía tokens y usuario en JSON
router.get(
  '/google/callback',
  passport.authenticate('google', { failureRedirect: '/login/failed', session: false }),
  (req, res) => {
    const accessToken = generateAccessToken(req.user);
    const refreshToken = generateRefreshToken(req.user);

    res.json({
      accessToken,
      refreshToken,
      user: {
        id: req.user.id,
        name: req.user.name,
        email: req.user.email,
        photo: req.user.photo,
      },
    });
  }
);

// Endpoint para refrescar access token - recibe refreshToken en body o headers
router.post('/refresh', (req, res) => {
  const refreshToken =
    req.body.refreshToken || req.headers['x-refresh-token'];

  if (!refreshToken) {
    return res.status(401).json({ error: 'No hay refresh token' });
  }

  try {
    const payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    // Crear nuevo access token
    const newAccessToken = jwt.sign(
      { id: payload.id },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    return res.json({ accessToken: newAccessToken });
  } catch (err) {
    return res.status(403).json({ error: 'Refresh token inválido o expirado' });
  }
});

// Logout - solo para el frontend limpiar tokens (aquí solo confirmamos)
router.post('/logout', (req, res) => {
  // No usamos cookies, no hay que limpiar nada en backend
  res.json({ message: 'Sesión cerrada correctamente' });
});

// Verificar usuario actual usando access token en Authorization header
router.get('/me', async (req, res) => {
  try {
    let userId;

    if (req.headers.authorization?.startsWith('Bearer ')) {
      const token = req.headers.authorization.replace('Bearer ', '');
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      userId = payload.id;
    }

    if (!userId) return res.json({ user: null });

    const db = req.app.get('db') || require('../config/db');

    const { rows } = await db.query(
      'SELECT id, name, email, photo, rol FROM users WHERE id = $1',
      [userId]
    );

    if (!rows || rows.length === 0) return res.json({ user: null });

    return res.json({ user: rows[0] });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expirado', user: null });
    }
    console.error('Error en /auth/me:', err);
    return res.status(500).json({ user: null });
  }
});

// Falla de login
router.get('/login/failed', (req, res) => {
  res.status(401).json({ success: false, message: 'Falló la autenticación con Google' });
});

module.exports = router;
