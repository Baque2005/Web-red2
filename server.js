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
require('dotenv').config();
require('./auth/googleAuth'); // Estrategia de Google

const app = express();
const pool = require('./config/db');
const authRoutes = require('./routes/auth');

const isDev = process.env.NODE_ENV === 'development';
const CLIENT_URL = isDev ? process.env.CLIENT_URL_DEV : process.env.CLIENT_URL_PROD;

// Crear carpeta uploads si no existe
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// Middlewares (¡deben ir antes de cualquier ruta!)
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

// Middleware para agregar usuario autenticado a onlineUsers en cada petición
let onlineUsers = new Set();
app.use((req, res, next) => {
  // Si está autenticado por sesión
  if (req.user && req.user.id) {
    onlineUsers.add(req.user.id);
  } else {
    // Si tiene JWT en el header Authorization
    const auth = req.headers.authorization;
    if (auth && auth.startsWith('Bearer ')) {
      try {
        const token = auth.replace('Bearer ', '');
        const user = jwt.verify(token, process.env.JWT_SECRET);
        if (user && user.id) {
          onlineUsers.add(user.id);
        }
      } catch (err) {
        // Token inválido, no agregar
      }
    }
  }
  next();
});

// Rutas de autenticación
app.use('/auth', authRoutes);

// Ruta para obtener usuarios online
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

// Configurar multer con nombre aleatorio y extensión .html
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = uuidv4();
    console.log(`Guardando archivo original: ${file.originalname}, mime: ${file.mimetype}, como: ${uniqueName}.html`);
    cb(null, uniqueName + '.html');
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
  fileFilter: (req, file, cb) => {
    console.log(`fileFilter: tipo mime recibido: ${file.mimetype}, archivo: ${file.originalname}`);
    if (file.mimetype === 'text/html') {
      cb(null, true);
    } else {
      cb(new Error('Solo se permiten archivos HTML'));
    }
  }
});

// Subida de archivos HTML con manejo explícito de error multer
app.post('/files/upload', (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      return res.status(400).json({ success: false, message: err.message });
    }
    next();
  });
}, async (req, res) => {
  // --- AUTENTICACIÓN POR SESIÓN O JWT ---
  let user = req.user;
  if (!user) {
    // Si no hay sesión, intenta con JWT
    const auth = req.headers.authorization;
    if (auth && auth.startsWith('Bearer ')) {
      try {
        user = jwt.verify(auth.replace('Bearer ', ''), process.env.JWT_SECRET);
      } catch {
        user = null;
      }
    }
  }
  if (!user || !user.id) {
    return res.status(401).json({ success: false, message: 'No autenticado' });
  }

  if (!req.file) {
    return res.status(400).json({ success: false, message: 'No se recibió archivo HTML' });
  }

  const { originalname, filename } = req.file;
  const file_data = filename;
  const user_id = user.id;

  try {
    await pool.query(
      'INSERT INTO html_files (user_id, filename, file_data, created_at) VALUES ($1, $2, $3, NOW())',
      [user_id, originalname, file_data]
    );
    res.json({ success: true, message: 'Archivo subido correctamente.' });
  } catch (err) {
    console.error('Error al guardar en DB:', err);
    res.status(500).json({ success: false, message: 'Error al guardar en la base de datos.' });
  }
});

// Listar archivos
app.get('/files', async (req, res) => {
  try {
    const { search = '', page = 1 } = req.query;
    const limit = 10;
    const offset = (parseInt(page, 10) - 1) * limit;

    const result = await pool.query(
      `SELECT f.id, f.filename, f.file_data, f.user_id, u.name AS user_name
       FROM html_files f
       JOIN users u ON f.user_id = u.id
       WHERE f.filename ILIKE $1
       ORDER BY f.created_at DESC
       LIMIT $2 OFFSET $3`,
      [`%${search}%`, limit, offset]
    );

    res.json({
      files: result.rows,
      hasMore: result.rows.length === limit
    });
  } catch (err) {
    console.error('Error al listar archivos:', err);
    res.status(500).json({ files: [], hasMore: false });
  }
});

// Descargar archivo
app.get('/files/download/:filedata', async (req, res) => {
  const fileName = req.params.filedata;
  const filePath = path.join(uploadDir, fileName);

  try {
    const result = await pool.query(
      'SELECT filename FROM html_files WHERE file_data = $1 LIMIT 1',
      [fileName]
    );
    const originalName = result.rows[0]?.filename || fileName;

    fs.access(filePath, fs.constants.F_OK, (err) => {
      if (err) {
        console.error('Archivo no encontrado en uploads:', filePath);
        return res.status(404).json({ success: false, message: 'Archivo no encontrado.' });
      }
      res.download(filePath, originalName);
    });

  } catch (err) {
    console.error('Error al descargar archivo:', err);
    res.status(500).json({ success: false, message: 'Error al descargar el archivo.' });
  }
});

// Eliminar archivo
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
    if (!req.user || req.user.id !== user_id) {
      return res.status(403).json({ success: false, message: 'No autorizado.' });
    }

    const filePath = path.join(uploadDir, file_data);
    fs.unlink(filePath, async (err) => {
      if (err) {
        console.error('Error al eliminar archivo físico:', err);
        return res.status(500).json({ success: false, message: 'Error al eliminar archivo físico.' });
      }
      await pool.query('DELETE FROM html_files WHERE id = $1', [req.params.id]);
      res.json({ success: true });
    });
  } catch (err) {
    console.error('Error al eliminar archivo:', err);
    res.status(500).json({ success: false, message: 'Error al eliminar el archivo.' });
  }
});

// Ver archivo HTML
app.get('/files/view/:filedata', (req, res) => {
  const fileName = req.params.filedata;
  const filePath = path.join(uploadDir, fileName);

  fs.access(filePath, fs.constants.F_OK, (err) => {
    if (err) {
      console.error('Archivo no encontrado:', filePath);
      return res.status(404).send('Archivo no encontrado');
    }
    res.sendFile(filePath);
  });
});

// Ruta ping para mantener la sesión activa
app.post('/users/ping', (req, res) => {
  res.status(200).json({ success: true });
});

// Ruta para testear la sesión y cookies
app.get('/test-session', (req, res) => {
  console.log('--- /test-session ---');
  console.log('Cookies:', req.headers.cookie);
  console.log('Session:', req.session);
  console.log('User:', req.user);
  console.log('isAuthenticated:', req.isAuthenticated && req.isAuthenticated());

  res.json({
    isAuthenticated: req.isAuthenticated ? req.isAuthenticated() : false,
    user: req.user || null,
    session: req.session,
    cookies: req.headers.cookie || null,
  });
});

// Servir archivos estáticos del frontend React
app.use('/uploads', express.static(uploadDir));
const buildPath = path.join(__dirname, 'build');
app.use(express.static(buildPath));

// Enviar index.html para cualquier ruta que NO sea API ni autenticación
app.get(/^\/(?!api|auth|files).*/, (req, res) => {
  res.sendFile(path.join(buildPath, 'index.html'), err => {
    if (err) {
      console.error('Error enviando index.html:', err);
      res.status(500).send('Error interno del servidor');
    }
  });
});

// Ruta base (opcional, solo para demo)
app.get('/', (req, res) => {
  res.send('Servidor corriendo 🚀');
});

// Iniciar servidor
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Servidor backend en http://localhost:${PORT}`);
});

app.post('/users/offline', (req, res) => {
  let userId = null;
  // Buscar por sesión
  if (req.user && req.user.id) {
    userId = req.user.id;
  } else {
    // Buscar por JWT
    const auth = req.headers.authorization;
    if (auth && auth.startsWith('Bearer ')) {
      try {
        const user = jwt.verify(auth.replace('Bearer ', ''), process.env.JWT_SECRET);
        if (user && user.id) userId = user.id;
      } catch {}
    }
  }
  if (userId) {
    onlineUsers.delete(userId);
  }
  res.status(200).json({ success: true });
});

