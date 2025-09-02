const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const passport = require('passport');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const sanitizeHtml = require('sanitize-html');
if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}
const dayjs = require('dayjs');
const { v4: uuidv4 } = require('uuid');
const { createClient } = require('@supabase/supabase-js');
const { publishBuffer } = require('./services/githubPagesPublisher');

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
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));

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

// CORS: SOLO deja el middleware cors bien configurado y elimina el manual
const corsOptions = {
  origin: CLIENT_URL,
  methods: ['GET','POST','DELETE','PUT','PATCH','OPTIONS'],
  allowedHeaders: ['Authorization', 'Content-Type', 'Accept', 'X-Requested-With'],
  credentials: false, // usas JWT por header, no cookies
  optionsSuccessStatus: 204,
};
app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));

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
require('./auth/googleAuth'); // <--- Esto debe ir ANTES de app.use('/auth', authRoutes)
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

// Subida de archivos HTML a GitHub Pages (sin restricción de login)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'file' && file.mimetype === 'text/html') return cb(null, true);
    if (file.fieldname === 'image' && file.mimetype.startsWith('image/')) return cb(null, true);
    cb(new Error('Solo se permiten archivos HTML y una imagen'));
  }
});

app.post('/files/upload', (req, res) => {
  upload.fields([{ name: 'file', maxCount: 1 }, { name: 'image', maxCount: 1 }])(req, res, async (err) => {
    if (err) return res.status(400).json({ success: false, message: err.message });

    // Cambia aquí: usa htmlFile en vez de req.file
    const htmlFile = req.files?.file?.[0];
    const imageFile = req.files?.image?.[0];
    if (!htmlFile) return res.status(400).json({ success: false, message: 'No se recibió archivo HTML' });
    if (!imageFile) return res.status(400).json({ success: false, message: 'No se recibió imagen de vista previa' });

    // Obtener user_id del JWT o sesión
    let userId = req.user?.id;
    const auth = req.headers.authorization;
    if (!userId && auth?.startsWith('Bearer ')) {
      try {
        const token = auth.replace('Bearer ', '');
        const user = jwt.verify(token, process.env.JWT_SECRET);
        if (user?.id) userId = user.id;
      } catch {}
    }
    if (!userId) {
      return res.status(401).json({ success: false, message: 'Debes iniciar sesión para subir archivos.' });
    }

    const tipo = req.body.tipo || '';
    const categoria = req.body.categoria || '';
    const descripcion = req.body.descripcion || '';
    // Nuevo: Lee epago como string ("gratuito" o "vip")
    let epago = 'gratuito';
    if (typeof req.body.epago === 'string' && ['vip', 'gratuito'].includes(req.body.epago)) {
      epago = req.body.epago;
    } else if (req.body.vip === 'true' || req.body.vip === true || req.body.vip === '1' || req.body.vip === 1) {
      epago = 'vip';
    }

    if (!tipo || !categoria) {
      return res.status(400).json({ success: false, message: 'Debes seleccionar tipo y categoría.' });
    }

    // --- Nueva lógica de ruta única ---
    const ext = (path.extname(htmlFile.originalname) || '.html').toLowerCase();
    if (!['.html', '.htm'].includes(ext)) {
      return res.status(400).json({ success: false, message: 'Solo se permiten archivos .html' });
    }
    const y = dayjs().format('YYYY');
    const m = dayjs().format('MM');
    const slug = uuidv4();
    const targetPath = `${y}/${m}/${slug}${ext}`;

    try {
      // 1. Subir a Supabase Storage (backup)
      const supabaseKey = `html-files/${targetPath}`;
      const { error: supaError } = await supabase
        .storage
        .from('html-files')
        .upload(targetPath, htmlFile.buffer, { upsert: false, contentType: 'text/html' });
      if (supaError && !String(supaError.message || '').toLowerCase().includes('already exists')) {
        return res.status(500).json({ success: false, message: 'Error al subir a Supabase: ' + supaError.message });
      }
      // 2. Obtener URL pública de Supabase
      const { data: publicData } = supabase
        .storage
        .from('html-files')
        .getPublicUrl(targetPath);
      const supabaseUrl = publicData?.publicUrl || null;

      // 3. Publicar en GitHub Pages
      const publicUrl = await publishBuffer({
        buffer: htmlFile.buffer,
        targetPath,
        message: `publish: ${htmlFile.originalname} -> ${targetPath}`
      });

      // 4. Subir imagen a Supabase Storage
      const imageExt = path.extname(imageFile.originalname) || '.jpg';
      const imagePath = `preview-images/${y}/${m}/${slug}${imageExt}`;
      const { error: imgError } = await supabase
        .storage
        .from('preview-images')
        .upload(imagePath, imageFile.buffer, { upsert: false, contentType: imageFile.mimetype });
      if (imgError && !String(imgError.message || '').toLowerCase().includes('already exists')) {
        return res.status(500).json({ success: false, message: 'Error al subir imagen: ' + imgError.message });
      }
      const { data: imgData } = supabase
        .storage
        .from('preview-images')
        .getPublicUrl(imagePath);
      const previewImageUrl = imgData?.publicUrl || null;

      // 5. Guarda en la base de datos ambas rutas (usa userId)
      await pool.query(
        'INSERT INTO html_files (user_id, filename, file_data, file_url, supabase_url, tipo, categoria, descripcion, preview_image_url, epago, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())',
        [userId, htmlFile.originalname, targetPath, publicUrl, supabaseUrl, tipo, categoria, descripcion, previewImageUrl, epago]
      );

      res.status(201).json({ success: true, message: 'Archivo subido correctamente.', publicUrl, supabaseUrl, previewImageUrl });
    } catch (err) {
      console.error('Error al subir a GitHub Pages/Supabase:', err);
      res.status(500).json({ success: false, message: err.message });
    }
  });
});

// Tabla likes: CREATE TABLE file_likes (id SERIAL PRIMARY KEY, file_id INT, user_id INT, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(file_id, user_id));
// ALTER TABLE html_files ADD COLUMN downloads INT DEFAULT 0;

app.get('/files', async (req, res) => {
  try {
    // Añade userId al destructuring
    const { search = '', user = '', tipo = '', categoria = '', page = 1, userId = '', limit = 20, orderBy = '' } = req.query;
    const pageNum = Math.max(1, parseInt(page, 10) || 1);
    const pageLimit = Math.max(1, Math.min(parseInt(limit, 10) || 20, 100));
    const offset = (pageNum - 1) * pageLimit;
    let query = `
      SELECT f.id, f.filename, f.file_data, f.file_url, f.user_id, u.name AS user_name, f.tipo, f.categoria, f.descripcion, f.downloads, f.preview_image_url, f.epago,
        (SELECT COUNT(*) FROM file_likes WHERE file_id = f.id) AS likes
      FROM html_files f
      JOIN users u ON f.user_id = u.id
      WHERE 1=1
    `;
    const params = [];
    let idx = 1;

    // Solo agrega filtro si el parámetro tiene valor no vacío
    if (search && search.trim() !== '') {
      query += ` AND f.filename ILIKE $${idx++}`;
      params.push(`%${search}%`);
    }
    if (user && user.trim() !== '') {
      query += ` AND u.name ILIKE $${idx++}`;
      params.push(`%${user}%`);
    }
    if (tipo && tipo.trim() !== '') {
      query += ` AND f.tipo = $${idx++}`;
      params.push(tipo);
    }
    if (categoria && categoria.trim() !== '') {
      query += ` AND f.categoria = $${idx++}`;
      params.push(categoria);
    }
    // Nuevo: filtro por userId (preferente para exactitud)
    if (userId && String(userId).trim() !== '') {
      query += ` AND f.user_id = $${idx++}`;
      params.push(Number(userId));
    }

    // Ordenamiento por descargas si se pide explícitamente
    if (orderBy === 'downloads') {
      query += ` ORDER BY f.downloads DESC, f.created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`;
    } else {
      query += ` ORDER BY f.created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`;
    }
    params.push(pageLimit, offset);

    const result = await pool.query(query, params);

    // Saber si hay más archivos para la siguiente página
    let hasMore = false;
    if (result.rows.length === pageLimit) {
      // Consulta rápida: ¿hay al menos 1 más?
      let countQuery = `
        SELECT 1 FROM html_files f
        JOIN users u ON f.user_id = u.id
        WHERE 1=1
      `;
      const countParams = [];
      let cidx = 1;
      if (search && search.trim() !== '') {
        countQuery += ` AND f.filename ILIKE $${cidx++}`;
        countParams.push(`%${search}%`);
      }
      if (user && user.trim() !== '') {
        countQuery += ` AND u.name ILIKE $${cidx++}`;
        countParams.push(`%${user}%`);
      }
      if (tipo && tipo.trim() !== '') {
        countQuery += ` AND f.tipo = $${cidx++}`;
        countParams.push(tipo);
      }
      if (categoria && categoria.trim() !== '') {
        countQuery += ` AND f.categoria = $${cidx++}`;
        countParams.push(categoria);
      }
      if (userId && String(userId).trim() !== '') {
        countQuery += ` AND f.user_id = $${cidx++}`;
        countParams.push(Number(userId));
      }
      countQuery += ` OFFSET $${cidx}`;
      countParams.push(offset + pageLimit);

      const countRes = await pool.query(countQuery, countParams);
      hasMore = countRes.rows.length > 0;
    }

    res.json({ files: result.rows, hasMore });
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
    // Cambia a ON CONFLICT (file_id, user_id) DO NOTHING
    await pool.query(
      'INSERT INTO file_likes (file_id, user_id) VALUES ($1, $2) ON CONFLICT (file_id, user_id) DO NOTHING',
      [fileId, userId]
    );
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
    // Busca el archivo por file_data
    const { rows } = await pool.query(
      'SELECT id, filename, supabase_url, downloads FROM html_files WHERE file_data = $1 LIMIT 1',
      [req.params.filedata]
    );
    if (!rows.length) {
      return res.status(404).json({ success: false, message: 'Archivo no encontrado.' });
    }
    // Incrementa descargas
    await pool.query('UPDATE html_files SET downloads = downloads + 1 WHERE id = $1', [rows[0].id]);
    // Redirige a la URL pública de Supabase Storage
    const supabaseUrl = rows[0].supabase_url;
    if (!supabaseUrl) {
      return res.status(404).json({ success: false, message: 'Archivo no disponible para descargar.' });
    }
    // Validación extra: ¿la URL realmente existe?
    // Opcional: puedes hacer un HEAD request para verificar si el archivo existe en Supabase
    // Pero normalmente si la URL está bien formada, debe funcionar.
    return res.redirect(supabaseUrl);
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
    // Elimina archivos de Supabase Storage antes de borrar html_files
    const { rows: files } = await pool.query('SELECT file_data FROM html_files WHERE user_id = $1', [userIdToDelete]);
    const keys = files.map(r => r.file_data);
    if (keys.length) {
      await supabase.storage.from('html-files').remove(keys);
    }
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
      // Archivo no encontrado, pero respondemos éxito para evitar error 404
      return res.json({ success: true, message: 'Archivo no encontrado pero considerado eliminado.' });
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
    return res.json({ success: true });
  } catch (err) {
    console.error('Error al eliminar archivo:', err);
    return res.status(500).json({ success: false, message: 'Error al eliminar el archivo.' });
  }
});

// 1. Requiere cookie-parser al inicio del archivo
const cookieParser = require('cookie-parser');
app.use(cookieParser());

// Endpoint para renovar el access token usando el refresh token de la cookie
app.post('/auth/refresh', (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.REFRESH_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    const newAccessToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    res.json({ accessToken: newAccessToken });
  });
});

// Archivos estáticos y SPA
app.use(express.static('public'));

app.use('/uploads', express.static(uploadDir));
const buildPath = path.join(__dirname, 'build');
app.use(express.static(buildPath));

// Elimina la línea duplicada (ya tienes app.use('/auth', authRoutes) arriba)
// app.use('/auth', authRoutes);

// Ruta raíz (opcional)
app.get('/', (req, res) => {
  res.send('Servidor corriendo 🚀');
});

// Catch-all seguro para SPA (NO captura '/', excluye prefijos de API/estáticos)
app.get(/^\/(?!api|auth|files|uploads)(?:.+)$/, (req, res) => {
  res.sendFile(path.join(buildPath, 'index.html'), err => {
    if (err) {
      console.error('Error enviando index.html:', err);
      res.status(500).send('Error interno del servidor');
    }
  });
});
app.get('/files/download/:year/:month/:filename', async (req, res) => {
  const { year, month, filename } = req.params;
  const filePath = `${year}/${month}/${filename}`;
  try {
    // Busca el archivo en la base de datos por file_data para incrementar descargas y obtener el nombre original
    const { rows } = await pool.query(
      'SELECT id, filename FROM html_files WHERE file_data = $1 LIMIT 1',
      [filePath]
    );
    if (rows.length) {
      await pool.query('UPDATE html_files SET downloads = downloads + 1 WHERE id = $1', [rows[0].id]);
    } else {
      return res.status(404).send('Archivo no encontrado en la base de datos.');
    }
    // Descarga el archivo como buffer desde Supabase Storage
    const { data, error } = await supabase
      .storage
      .from('html-files')
      .download(filePath);

    if (error || !data) {
      return res.status(404).send('Archivo no encontrado en Supabase.');
    }

    // Usa el nombre original del archivo para la descarga
    const originalFilename = rows[0].filename || filename;

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(originalFilename)}"`);

    if (typeof data.pipe === 'function') {
      data.pipe(res);
    } else if (Buffer.isBuffer(data)) {
      res.end(data);
    } else if (data.arrayBuffer) {
      data.arrayBuffer().then(buf => {
        res.end(Buffer.from(buf));
      });
    } else {
      res.status(500).send('No se pudo procesar el archivo.');
    }
  } catch (err) {
    res.status(500).send('Error interno del servidor.');
  }
});

// ❌ Elimina este bloque de ejemplo fuera de cualquier función o endpoint:
// const { data: files, error } = await supabase
//   .storage
//   .from('html-files')
//   .list(`${year}/${month}/`, {
//     limit: 1000,
//     offset: 0,
//     sortBy: { column: 'name', order: 'asc' }
//   });
// if (error) {
//   console.error('Error al listar archivos en Supabase:', error);
// } else {
//   console.log('Archivos encontrados en Supabase:', files.length);
// }

// Iniciar servidor
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Servidor backend en http://localhost:${PORT}`);
});

// Endpoint de descarga directa desde Supabase Storage usando ruta completa
// Endpoint de descarga directa desde Supabase Storage usando ruta completa

// Solución: Cambia el tipo de módulo a CommonJS
// 1. Abre tu package.json y asegúrate de que NO tienes "type": "module"
// 2. Si tienes "type": "module", elimínalo o cámbialo a "type": "commonjs"
// 3. Así puedes usar require(...) normalmente

// Si necesitas usar ES modules, cambia todas las líneas require(...) por import ... from ... y usa la extensión .mjs
// Pero para tu proyecto actual, solo asegúrate de que package.json NO tenga "type": "module"
// Solución: Cambia el tipo de módulo a CommonJS
// 1. Abre tu package.json y asegúrate de que NO tienes "type": "module"
// 2. Si tienes "type": "module", elimínalo o cámbialo a "type": "commonjs"
// 3. Así puedes usar require(...) normalmente

// Si necesitas usar ES modules, cambia todas las líneas require(...) por import ... from ... y usa la extensión .mjs
// Pero para tu proyecto actual, solo asegúrate de que package.json NO tenga "type": "module"

// Endpoint para editar archivo (descripción, tipo, categoría, imagen, vip)
app.post('/files/edit/:id', (req, res) => {
  upload.fields([{ name: 'image', maxCount: 1 }])(req, res, async (err) => {
    if (err) return res.status(400).json({ success: false, message: err.message });

    const fileId = req.params.id;
    // Solo toma los campos si existen y no son undefined
    const descripcion = typeof req.body.descripcion === 'string' ? req.body.descripcion : undefined;
    const tipo = typeof req.body.tipo === 'string' ? req.body.tipo : undefined;
    const categoria = typeof req.body.categoria === 'string' ? req.body.categoria : undefined;
    const epago = typeof req.body.epago === 'string' && ['vip', 'gratuito'].includes(req.body.epago)
      ? req.body.epago
      : undefined;
    const imageFile = req.files?.image?.[0];

    // Autenticación: solo el dueño o admin puede editar
    let userId = req.user?.id;
    const auth = req.headers.authorization;
    if (!userId && auth?.startsWith('Bearer ')) {
      try {
        const user = jwt.verify(auth.replace('Bearer ', ''), process.env.JWT_SECRET);
        if (user?.id) userId = user.id;
      } catch {}
    }
    if (!userId) return res.status(401).json({ success: false, message: 'No autenticado' });

    // Verifica dueño o admin
    const { rows } = await pool.query('SELECT user_id, file_data FROM html_files WHERE id = $1', [fileId]);
    if (!rows.length) return res.status(404).json({ success: false, message: 'Archivo no encontrado' });
    const fileRow = rows[0];
    let isAdmin = false;
    const rolRes = await pool.query('SELECT rol FROM users WHERE id = $1', [userId]);
    isAdmin = rolRes.rows[0]?.rol === 'admin';
    if (String(fileRow.user_id) !== String(userId) && !isAdmin) {
      return res.status(403).json({ success: false, message: 'No autorizado' });
    }

    let previewImageUrl = null;
    if (imageFile) {
      // Sube la nueva imagen a Supabase Storage (sobrescribe)
      const [year, month, ...rest] = fileRow.file_data.split('/');
      const slug = rest.join('/').replace(/\.[^.]+$/, ''); // sin extensión
      const imageExt = path.extname(imageFile.originalname) || '.jpg';
      const imagePath = `preview-images/${year}/${month}/${slug}${imageExt}`;
      const { error: imgError } = await supabase
        .storage
        .from('preview-images')
        .upload(imagePath, imageFile.buffer, { upsert: true, contentType: imageFile.mimetype });
      if (imgError && !String(imgError.message || '').toLowerCase().includes('already exists')) {
        return res.status(500).json({ success: false, message: 'Error al subir imagen: ' + imgError.message });
      }
      const { data: imgData } = supabase
        .storage
        .from('preview-images')
        .getPublicUrl(imagePath);
      previewImageUrl = imgData?.publicUrl || null;
    }

    // Solo agrega campos que realmente se van a actualizar
    const updates = [];
    const params = [];
    let idx = 1;
    if (descripcion !== undefined) { updates.push(`descripcion = $${idx++}`); params.push(descripcion); }
    if (tipo !== undefined) { updates.push(`tipo = $${idx++}`); params.push(tipo); }
    if (categoria !== undefined) { updates.push(`categoria = $${idx++}`); params.push(categoria); }
    if (previewImageUrl) { updates.push(`preview_image_url = $${idx++}`); params.push(previewImageUrl); }
    if (epago !== undefined) { updates.push(`epago = $${idx++}`); params.push(epago); }

    if (!updates.length) return res.json({ success: true }); // Nada que actualizar

    params.push(fileId);
    try {
      await pool.query(
        `UPDATE html_files SET ${updates.join(', ')} WHERE id = $${idx}`,
        params
      );
      res.json({ success: true, previewImageUrl });
    } catch (error) {
      console.error('Error en /files/edit/:id:', error);
      res.status(500).json({ success: false, message: 'Error al actualizar el archivo.' });
    }
  });
});

// Tu backend ya implementa el flujo principal para archivos VIP:
// - Pago de subida VIP (el frontend lo gestiona, el backend solo recibe el archivo tras el pago)
// - Subida de archivos VIP y gratuitos con distinción por campo epago
// - Registro de descargas y likes
// - Cálculo de ganancias por descargas (descargas * 0.9 para el autor, * 0.1 para el admin)
// - El backend puede consultar archivos por usuario y tipo (VIP/gratuito)
// - El backend permite eliminar y editar archivos, y gestiona imágenes de vista previa
// - El backend permite listar usuarios y archivos, y eliminar usuarios (solo admin)
// - El backend no realiza pagos automáticos a PayPal, pero puedes calcular las ganancias y mostrar el saldo

// Si quieres automatizar los pagos (payouts) a la cuenta PayPal del usuario, necesitas integrar PayPal Payouts o Stripe Connect en el backend y pedir al usuario que vincule su cuenta PayPal en su perfil.

// El flujo actual es funcional para la gestión de archivos, descargas y cálculo de ganancias, pero los pagos automáticos requieren integración adicional con la API de pagos.

// Endpoint para saber si el usuario ya compró un archivo VIP
app.get('/files/:id/purchased', async (req, res) => {
  let userId = req.user?.id;
  const auth = req.headers.authorization;
  if (!userId && auth?.startsWith('Bearer ')) {
    try {
      const user = jwt.verify(auth.replace('Bearer ', ''), process.env.JWT_SECRET);
      if (user?.id) userId = user.id;
    } catch {}
  }
  if (!userId) return res.json({ purchased: false });

  const fileId = req.params.id;
  try {
    // Busca en la tabla de compras si el usuario ya compró este archivo
    // Si no tienes la tabla, crea: CREATE TABLE file_purchases (id SERIAL PRIMARY KEY, file_id INT, user_id INT, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(file_id, user_id));
    const { rows } = await pool.query(
      'SELECT 1 FROM file_purchases WHERE file_id = $1 AND user_id = $2 LIMIT 1',
      [fileId, userId]
    );
    res.json({ purchased: rows.length > 0 });
  } catch {
    res.json({ purchased: false });
  }
});

// Endpoint para registrar la compra de un archivo VIP
app.post('/files/:id/purchase', async (req, res) => {
  let userId = req.user?.id;
  const auth = req.headers.authorization;
  if (!userId && auth?.startsWith('Bearer ')) {
    try {
      const user = jwt.verify(auth.replace('Bearer ', ''), process.env.JWT_SECRET);
      if (user?.id) userId = user.id;
    } catch {}
  }
  if (!userId) return res.status(401).json({ success: false });

  const fileId = req.params.id;
  try {
    await pool.query(
      'INSERT INTO file_purchases (file_id, user_id) VALUES ($1, $2) ON CONFLICT (file_id, user_id) DO NOTHING',
      [fileId, userId]
    );
    res.json({ success: true });
  } catch {
    res.status(500).json({ success: false });
  }
});
