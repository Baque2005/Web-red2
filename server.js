const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const passport = require('passport');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const sanitizeHtml = require('sanitize-html');
require('dotenv').config();
require('./auth/googleAuth'); // Estrategia de Google
const { createClient } = require('@supabase/supabase-js');

const app = express();
const pool = require('./config/db');
const authRoutes = require('./routes/auth');

const isDev = process.env.NODE_ENV === 'development';
const CLIENT_URL = isDev ? process.env.CLIENT_URL_DEV : process.env.CLIENT_URL_PROD;

// Configuración de Supabase
const SUPABASE_URL = 'https://dpkubmzabfqwgduifpzo.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// Crear carpeta 'uploads' si no existe
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  store: new PgSession({
    pool: pool,
    tableName: 'session',
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: !isDev,
    httpOnly: true,
    sameSite: isDev ? 'lax' : 'none',
    maxAge: 24 * 60 * 60 * 1000,
  }
}));

app.use(passport.initialize());
app.use(passport.session());

app.use(cors({
  origin: CLIENT_URL,
  credentials: true,
}));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', CLIENT_URL);
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});

// Usuarios online
let onlineUsers = new Set();
let onlineTimestamps = {};

app.use((req, res, next) => {
  let userId = null;
  if (req.user?.id) {
    userId = req.user.id;
  } else {
    const auth = req.headers.authorization;
    if (auth?.startsWith('Bearer ')) {
      try {
        const token = auth.replace('Bearer ', '');
        const user = jwt.verify(token, process.env.JWT_SECRET);
        if (user?.id) userId = user.id;
      } catch {}
    }
  }

  if (userId) {
    onlineUsers.add(userId);
    onlineTimestamps[userId] = Date.now();
  }

  next();
});

setInterval(() => {
  const now = Date.now();
  for (const userId of onlineUsers) {
    if (!onlineTimestamps[userId] || now - onlineTimestamps[userId] > 15000) {
      onlineUsers.delete(userId);
      delete onlineTimestamps[userId];
    }
  }
}, 10000);

// Rutas
app.use('/auth', authRoutes);

app.get('/users/online', async (req, res) => {
  try {
    if (onlineUsers.size === 0) return res.json({ users: [] });
    const ids = Array.from(onlineUsers);
    const result = await pool.query(
      'SELECT id, name, photo FROM users WHERE id = ANY($1::int[])',
      [ids]
    );
    res.json({ users: result.rows });
  } catch (err) {
    console.error('Error al obtener usuarios online:', err);
    res.json({ users: [] });
  }
});

// Subida de archivos HTML a Supabase Storage
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'text/html') {
      cb(null, true);
    } else {
      cb(new Error('Solo se permiten archivos HTML'));
    }
  }
});

app.post('/files/upload', (req, res) => {
  upload.single('file')(req, res, async (err) => {
    if (err) return res.status(400).json({ success: false, message: err.message });

    let user = req.user;
    if (!user) {
      const auth = req.headers.authorization;
      if (auth?.startsWith('Bearer ')) {
        try {
          user = jwt.verify(auth.replace('Bearer ', ''), process.env.JWT_SECRET);
        } catch {}
      }
    }

    if (!user?.id) {
      return res.status(401).json({ success: false, message: 'No autenticado' });
    }

    if (!req.file) {
      return res.status(400).json({ success: false, message: 'No se recibió archivo HTML' });
    }

    // Recoge los nuevos campos del formulario
    const tipo = req.body.tipo || '';
    const categoria = req.body.categoria || '';
    const descripcion = req.body.descripcion || '';
    if (!tipo || !categoria) {
      return res.status(400).json({ success: false, message: 'Debes seleccionar tipo y categoría.' });
    }

    const uniqueName = uuidv4() + '.html';
    const { originalname, buffer } = req.file;

    try {
      const { error } = await supabase.storage
        .from('html-files')
        .upload(uniqueName, buffer, {
          contentType: 'text/html',
          upsert: true,
        });

      if (error) {
        console.error('Error al subir a Supabase:', error);
        return res.status(500).json({ success: false, message: error.message });
      }

      const publicUrl = `${SUPABASE_URL}/storage/v1/object/public/html-files/${uniqueName}`;
      await pool.query(
        'INSERT INTO html_files (user_id, filename, file_data, file_url, tipo, categoria, descripcion, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())',
        [user.id, originalname, uniqueName, publicUrl, tipo, categoria, descripcion]
      );

      res.json({ success: true, message: 'Archivo subido correctamente.' });
    } catch (err) {
      console.error('Error al guardar en la base de datos:', err);
      res.status(500).json({ success: false, message: err.message });
    }
  });
});

// Tabla likes: CREATE TABLE file_likes (id SERIAL PRIMARY KEY, file_id INT, user_id INT, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(file_id, user_id));
// ALTER TABLE html_files ADD COLUMN downloads INT DEFAULT 0;

app.get('/files', async (req, res) => {
  try {
    const { search = '', user = '', tipo = '', categoria = '', page = 1 } = req.query;
    const limit = 10;
    const offset = (parseInt(page) - 1) * limit;
    let query = `
      SELECT f.id, f.filename, f.file_data, f.user_id, u.name AS user_name, f.tipo, f.categoria, f.descripcion, f.downloads,
        (SELECT COUNT(*) FROM file_likes WHERE file_id = f.id) AS likes
      FROM html_files f
      JOIN users u ON f.user_id = u.id
      WHERE 1=1
    `;
    const params = [];
    let idx = 1;

    if (search) {
      query += ` AND f.filename ILIKE $${idx++}`;
      params.push(`%${search}%`);
    }
    if (user) {
      query += ` AND u.name ILIKE $${idx++}`;
      params.push(`%${user}%`);
    }
    if (tipo) {
      query += ` AND f.tipo = $${idx++}`;
      params.push(tipo);
    }
    if (categoria) {
      query += ` AND f.categoria = $${idx++}`;
      params.push(categoria);
    }

    // Si no hay filtros, no agregues LIMIT/OFFSET (para evitar error de parámetros)
    if (params.length > 0) {
      query += ` ORDER BY f.created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`;
      params.push(limit, offset);
    } else {
      query += ` ORDER BY f.created_at DESC`;
    }

    const result = await pool.query(query, params);
    res.json({ files: result.rows, hasMore: params.length > 0 ? result.rows.length === limit : false });
  } catch (err) {
    console.error('Error al listar archivos:', err);
    res.status(500).json({ files: [], hasMore: false });
  }
});

app.get('/files/:id/likes', async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await pool.query('SELECT COUNT(*)::int AS likes FROM file_likes WHERE file_id = $1', [id]);
    res.json({ likes: rows[0]?.likes || 0 });
  } catch {
    res.json({ likes: 0 });
  }
});

app.post('/files/:id/like', async (req, res) => {
  let userId = req.user?.id;
  const auth = req.headers.authorization;
  if (!userId && auth?.startsWith('Bearer ')) {
    try {
      const user = jwt.verify(auth.replace('Bearer ', ''), process.env.JWT_SECRET);
      if (user?.id) userId = user.id;
    } catch {}
  }
  if (!userId) return res.status(401).json({ success: false, message: 'No autenticado' });
  const fileId = req.params.id;
  try {
    await pool.query('INSERT INTO file_likes (file_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [fileId, userId]);
    const { rows } = await pool.query('SELECT COUNT(*)::int AS likes FROM file_likes WHERE file_id = $1', [fileId]);
    res.json({ success: true, likes: rows[0]?.likes || 0 });
  } catch {
    res.status(500).json({ success: false });
  }
});

app.post('/files/:id/unlike', async (req, res) => {
  let userId = req.user?.id;
  const auth = req.headers.authorization;
  if (!userId && auth?.startsWith('Bearer ')) {
    try {
      const user = jwt.verify(auth.replace('Bearer ', ''), process.env.JWT_SECRET);
      if (user?.id) userId = user.id;
    } catch {}
  }
  if (!userId) return res.status(401).json({ success: false, message: 'No autenticado' });
  const fileId = req.params.id;
  try {
    await pool.query('DELETE FROM file_likes WHERE file_id = $1 AND user_id = $2', [fileId, userId]);
    const { rows } = await pool.query('SELECT COUNT(*)::int AS likes FROM file_likes WHERE file_id = $1', [fileId]);
    res.json({ success: true, likes: rows[0]?.likes || 0 });
  } catch {
    res.status(500).json({ success: false });
  }
});

app.get('/files/:id/liked', async (req, res) => {
  let userId = req.user?.id;
  const auth = req.headers.authorization;
  if (!userId && auth?.startsWith('Bearer ')) {
    try {
      const user = jwt.verify(auth.replace('Bearer ', ''), process.env.JWT_SECRET);
      if (user?.id) userId = user.id;
    } catch {}
  }
  if (!userId) return res.json({ liked: false });
  const fileId = req.params.id;
  const { rows } = await pool.query('SELECT 1 FROM file_likes WHERE file_id = $1 AND user_id = $2 LIMIT 1', [fileId, userId]);
  res.json({ liked: rows.length > 0 });
});

app.get('/files/download/:filedata', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, filename, file_url, downloads FROM html_files WHERE file_data = $1 LIMIT 1',
      [req.params.filedata]
    );
    if (!rows.length) return res.status(404).json({ success: false, message: 'Archivo no encontrado.' });
    // Incrementa descargas
    await pool.query('UPDATE html_files SET downloads = downloads + 1 WHERE id = $1', [rows[0].id]);
    res.redirect(rows[0].file_url);
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error al descargar el archivo.' });
  }
});

app.get('/files/view/:filedata', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT file_url FROM html_files WHERE file_data = $1 LIMIT 1',
      [req.params.filedata]
    );
    if (!rows.length) {
      return res.status(404).send('<div>Archivo HTML no encontrado.</div>');
    }

    const response = await fetch(rows[0].file_url);
    if (!response.ok) {
      return res.status(404).send('<div>No se pudo cargar el archivo desde Supabase.</div>');
    }

    const html = await response.text();
    const cleanHtml = sanitizeHtml(html, {
      allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img', 'h1', 'h2', 'pre', 'code']),
      allowedAttributes: {
        a: ['href', 'title', 'target'],
        img: ['src', 'alt'],
        '*': ['style', 'class']
      },
    });
    res.setHeader('Content-Type', 'text/html');
    res.send(cleanHtml);
  } catch (err) {
    res.status(500).send('<div>Error al mostrar el archivo HTML.</div>');
  }
});

// Ping y offline
app.post('/users/ping', (req, res) => {
  let userId = req.user?.id;
  const auth = req.headers.authorization;
  if (!userId && auth?.startsWith('Bearer ')) {
    try {
      const user = jwt.verify(auth.replace('Bearer ', ''), process.env.JWT_SECRET);
      if (user?.id) userId = user.id;
    } catch {}
  }

  if (userId) {
    onlineUsers.add(userId);
    onlineTimestamps[userId] = Date.now();
  }

  res.status(200).json({ success: true });
});

app.post('/users/offline', (req, res) => {
  let userId = req.user?.id;
  const auth = req.headers.authorization;
  if (!userId && auth?.startsWith('Bearer ')) {
    try {
      const user = jwt.verify(auth.replace('Bearer ', ''), process.env.JWT_SECRET);
      if (user?.id) userId = user.id;
    } catch {}
  }

  if (userId) {
    onlineUsers.delete(userId);
    delete onlineTimestamps[userId];
  }

  res.status(200).json({ success: true });
});

// Test sesión
app.get('/test-session', (req, res) => {
  res.json({
    isAuthenticated: req.isAuthenticated?.() || false,
    user: req.user || null,
    session: req.session,
    cookies: req.headers.cookie || null,
  });
});

// Obtener todos los usuarios (solo admin)
app.get('/users/all', async (req, res) => {
  let user = req.user;
  const auth = req.headers.authorization;
  if (!user && auth?.startsWith('Bearer ')) {
    try {
      user = jwt.verify(auth.replace('Bearer ', ''), process.env.JWT_SECRET);
    } catch {}
  }

  // Consulta el rol del usuario autenticado
  let isAdmin = false;
  if (user && user.id) {
    const result = await pool.query('SELECT rol FROM users WHERE id = $1', [user.id]);
    isAdmin = result.rows[0]?.rol === 'admin';
  }
  if (!isAdmin) {
    return res.status(403).json({ users: [] });
  }

  try {
    const result = await pool.query('SELECT id, name, email, photo, rol FROM users ORDER BY id');
    res.json({ users: result.rows });
  } catch (err) {
    res.status(500).json({ users: [] });
  }
});

// Eliminar usuario (solo admin)
app.delete('/users/delete/:id', async (req, res) => {
  let user = req.user;
  const auth = req.headers.authorization;
  if (!user && auth?.startsWith('Bearer ')) {
    try {
      user = jwt.verify(auth.replace('Bearer ', ''), process.env.JWT_SECRET);
    } catch {}
  }

  // Consulta el rol del usuario autenticado
  let isAdmin = false;
  if (user && user.id) {
    const result = await pool.query('SELECT rol FROM users WHERE id = $1', [user.id]);
    isAdmin = result.rows[0]?.rol === 'admin';
  }
  if (!isAdmin) {
    return res.status(403).json({ success: false, message: 'No autorizado.' });
  }

  const userIdToDelete = req.params.id;
  try {
    await pool.query('DELETE FROM html_files WHERE user_id = $1', [userIdToDelete]);
    await pool.query('DELETE FROM users WHERE id = $1', [userIdToDelete]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error al eliminar usuario.' });
  }
});

// Eliminar archivo (admin puede eliminar cualquiera)
app.delete('/files/delete/:id', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT file_data, user_id FROM html_files WHERE id = $1',
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Archivo no encontrado.' });
    }

    const { file_data, user_id } = result.rows[0];

    // Autenticación
    let currentUserId = req.user && req.user.id ? req.user.id : null;
    let isAdmin = false;
    if (!currentUserId) {
      const auth = req.headers.authorization;
      if (auth && auth.startsWith('Bearer ')) {
        try {
          const user = jwt.verify(auth.replace('Bearer ', ''), process.env.JWT_SECRET);
          if (user && user.id) currentUserId = user.id;
        } catch {}
      }
    }
    if (currentUserId) {
      const result = await pool.query('SELECT rol FROM users WHERE id = $1', [currentUserId]);
      isAdmin = result.rows[0]?.rol === 'admin';
    }

    // Permitir al admin eliminar cualquier archivo
    if (!currentUserId || (String(currentUserId) !== String(user_id) && !isAdmin)) {
      return res.status(403).json({ success: false, message: 'No autorizado.' });
    }

    // Elimina archivo de Supabase Storage
    const { error: supaError } = await supabase.storage
      .from('html-files')
      .remove([file_data]);

    if (supaError) {
      if (
        supaError.message &&
        supaError.message.toLowerCase().includes('not found')
      ) {
        // Continúa, el archivo ya no existe en storage
      } else {
        console.error('Error al eliminar en Supabase:', supaError);
        return res.status(500).json({ success: false, message: 'Error al eliminar archivo en Supabase: ' + supaError.message });
      }
    }

    await pool.query('DELETE FROM html_files WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Error al eliminar archivo:', err);
    res.status(500).json({ success: false, message: 'Error al eliminar el archivo.' });
  }
});

// Archivos estáticos y SPA
app.use('/uploads', express.static(uploadDir));
const buildPath = path.join(__dirname, 'build');
app.use(express.static(buildPath));

app.get(/^\/(?!api|auth|files).*/, (req, res) => {
  res.sendFile(path.join(buildPath, 'index.html'), err => {
    if (err) {
      console.error('Error enviando index.html:', err);
      res.status(500).send('Error interno del servidor');
    }
  });
});

// Ruta raíz
app.get('/', (req, res) => {
  res.send('Servidor corriendo 🚀');
});

// Iniciar servidor
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Servidor backend en http://localhost:${PORT}`);
});
