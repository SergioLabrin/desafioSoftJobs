const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const { Pool } = require('pg');
require('dotenv').config(); // Para usar variables de entorno

const app = express();
const port = process.env.PORT || 3001;
const SECRET_KEY = process.env.SECRET_KEY || 'tu_secreta_llave';

// Configuración de CORS para permitir solicitudes desde el frontend
app.use(cors({
    origin: 'http://localhost:3000' // Ajusta esto al puerto que usa tu frontend
}));

app.use(express.json());

// Configuración de la base de datos
const pool = new Pool({
    user: process.env.DB_USER || 'tu_usuario',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'softjobs',
    password: process.env.DB_PASSWORD || 'tu_contraseña',
    port: process.env.DB_PORT || 5432,
});

// Middleware para verificar tokens
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: 'Token no proporcionado' });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Token inválido' });
        req.userEmail = decoded.email;
        next();
    });
};

// Ruta para registrar un nuevo usuario
app.post('/usuarios', async (req, res) => {
    const { email, password, rol, lenguage } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4) RETURNING *',
            [email, hashedPassword, rol, lenguage]
        );
        res.json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: 'Error registrando el usuario' });
    }
});

// Ruta para login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        const user = result.rows[0];
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Contraseña incorrecta' });

        const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: 'Error en el inicio de sesión' });
    }
});

// Ruta para obtener datos de un usuario autenticado
app.get('/usuarios', verifyToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [req.userEmail]);
        res.json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: 'Error obteniendo el usuario' });
    }
});

// Middleware para loguear todas las peticiones
app.use((req, res, next) => {
    console.log(`Ruta: ${req.url} - Método: ${req.method}`);
    next();
});

// Manejo de errores
app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: 'Error interno del servidor' });
});

app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});
