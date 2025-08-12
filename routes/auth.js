const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const router = express.Router();

const isDev = process.env.NODE_ENV === 'development';
const CLIENT_URL = isDev
  ? process.env.CLIENT_URL_DEV
  : process.env.CLIENT_URL_PROD;

// Función para crear access token (dura poco)
const generateAccessToken = (user) => {
  return jwt.sign(
    { id: user.id, name: user.name, email: user.email, photo: user.photo },
    process.env.JWT_SECRET,
    { expiresIn: '15m' } // dura 15 minutos
  );
};

// Función para crear refresh token (dura más)
const generateRefreshToken = (user) => {
  return jwt.sign(
    { id: user.id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' } // dura 7 días
  );
};

// Middleware para validar JWT en rutas protegidas
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    try {
      const user = jwt.verify(token, process.env.JWT_SECRET);
      req.user = user;
      next();
    } catch (err) {
      return res.status(403).json({ error: 'Token inválido o expirado' });
    }
  } else {
    return res.status(401).json({ error: 'No se proporcionó token' });
  }
};

// 👉 Ruta para iniciar sesión con Google
router.get('/google', passport.authenticate('google', {
  scope: ['profile', 'email'],
  prompt: 'select_account',
}));

// 👉 Callback de Google
router.get(
  '/google/callback',
  passport.authenticate('google', { failureRedirect: '/login/failed', session: false }),
  (req, res) => {
    const accessToken = generateAccessToken(req.user);
    const refreshToken = generateRefreshToken(req.user);

    // Enviar ambos tokens al frontend en JSON
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

// 👉 Endpoint para refrescar access token
// Ahora espera refresh token en body JSON { refreshToken: '...' }
router.post('/refresh', (req, res) => {
  // Evitar error si req.body es undefined o no tiene refreshToken
  const refreshToken = req.body?.refreshToken;
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

// 👉 Ruta de logout (solo responde para frontend borrar tokens)
router.post('/logout', (req, res) => {
  // No hay cookie que limpiar en este esquema
  // Solo confirmar logout para que el frontend borre tokens localmente
  res.json({ message: 'Sesión cerrada correctamente' });
});

// 👉 Verificar si la sesión de Passport sigue activa
router.get('/login/success', (req, res) => {
  if (req.isAuthenticated && req.isAuthenticated()) {
    res.status(200).json({ success: true, user: req.user });
  } else {
    res.status(401).json({ success: false, message: 'No autenticado' });
  }
});

// 👉 Falla de login
router.get('/login/failed', (req, res) => {
  res.status(401).json({ success: false, message: 'Falló la autenticación con Google' });
});

// 👉 Obtener usuario actual con JWT (ruta protegida)
router.get('/me', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.id;

    const { rows } = await req.app.get('db')?.query?.(
      'SELECT id, name, email, photo, rol FROM users WHERE id = $1',
      [userId]
    ) || await require('../config/db').query(
      'SELECT id, name, email, photo, rol FROM users WHERE id = $1',
      [userId]
    );

    if (!rows || rows.length === 0) return res.json({ user: null });

    return res.json({ user: rows[0] });
  } catch (err) {
    console.error('Error en /auth/me:', err);
    return res.status(500).json({ user: null });
  }
});

module.exports = router;
