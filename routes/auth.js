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

    // Guardar refresh token en cookie segura
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: !isDev,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 días
      path: '/',
    });

    // Redirigir con access token en URL o enviarlo por JSON
    res.redirect(`${CLIENT_URL}/?token=${accessToken}`);
  }
);

// 👉 Endpoint para refrescar access token
router.get('/refresh', (req, res) => {
  const refreshToken = req.cookies?.refreshToken;
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

// 👉 Ruta de logout para borrar cookie refreshToken
router.get('/logout', (req, res) => {
  // Si usas Passport con sesión, puedes hacer req.logout() aquí
  if (req.logout) req.logout();

  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: !isDev,
    sameSite: 'strict',
    path: '/',
  });

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

// 👉 Obtener usuario actual con JWT
router.get('/me', async (req, res) => {
  try {
    let userId = req.user?.id;

    // Si usas JWT en headers
    if (!userId && req.headers.authorization?.startsWith('Bearer ')) {
      const token = req.headers.authorization.replace('Bearer ', '');
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      userId = payload.id;
    }

    if (!userId) return res.json({ user: null });

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
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expirado', user: null });
    }
    console.error('Error en /auth/me:', err);
    return res.status(500).json({ user: null });
  }
});

module.exports = router;
