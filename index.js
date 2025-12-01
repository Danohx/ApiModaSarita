// ===== LIBRERÍAS =====
import express from "express";
import dotenv from "dotenv";
import cors from 'cors';
import pool from "./db/db.js";

// ===== IMPORTAR RUTAS =====
import authRoutes from "./routes/auth.routes.js";
import securityRoutes from "./routes/security.routes.js";

import rateLimit from 'express-rate-limit';
import helmet from "helmet";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// Vercel necesita confiar en el proxy para saber la IP real del usuario
app.set('trust proxy', 1);

// ===== MIDDLEWARES GLOBALES (El orden importa) =====
app.use(helmet());
app.use(express.json()); // <--- Importante: Esto va antes de las rutas y limiters

// --- CONFIGURACIÓN CORS MEJORADA ---
// Lista blanca de orígenes permitidos
const whitelist = [
  process.env.FRONTEND_URL,             // Tu frontend en Vercel
  "https://frontend-moda-sarita.vercel.app", // Hardcodeado por seguridad extra
  "http://localhost:5173",              // Tu frontend local (Vite)
  "http://localhost:3000"               // Postman o pruebas locales
];

app.use(cors({
  origin: function (origin, callback) {
    // Permitir requests sin origen (como apps móviles o Postman/cURL)
    if (!origin) return callback(null, true);
    
    if (whitelist.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log("Bloqueado por CORS:", origin); // Para depurar en Vercel logs
      callback(new Error('No permitido por CORS'));
    }
  },
  credentials: true, // Importante si usas cookies o headers seguros
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// --- RATE LIMITER ---
const loginLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutos
    max: 3, 
    message: { 
        mensaje: "⛔ Demasiados intentos. Por seguridad, espera 5 minutos." 
    },
    standardHeaders: true, 
    legacyHeaders: false,
    keyGenerator: (req, res) => {
        // Validación extra por si req.body llega vacío
        if (req.body && req.body.correo) {
            return req.body.correo; 
        }
        return req.ip; 
    }
});

// ===== DEFINICIÓN DE RUTAS =====
// Aplicamos el limiter solo a rutas sensibles
app.use("/api/auth/login", loginLimiter);
app.use("/api/auth/2fa-verify", loginLimiter);

app.use("/api/auth", authRoutes);
app.use("/api/security", securityRoutes);

// ===== HEALTH CHECK (Tu HTML bonito) =====
app.get("/", (req, res) => {
  pool.query('SELECT 1 + 1 AS result', (err, results) => {
    
    let dbStatus = "";
    let statusColor = "";

    if (err) {
      console.error("❌ Health check - Error DB:", err.message);
      dbStatus = "Base de Datos: Desconectada";
      statusColor = "#c62828";
    } else {
      // console.log("✅ Health check - DB Conectada"); // Comentado para no ensuciar logs
      dbStatus = "Base de Datos: Conectada";
      statusColor = "#2e7d32";
    }

    const htmlResponse = `
      <html lang="es">
      <head>
        <meta charset="UTF-8">
        <title>Estado del Backend</title>
        <style>
          body { font-family: sans-serif; display: grid; place-items: center; min-height: 90vh; background-color: #f8f6f7; color: #221019; }
          .container { background-color: #ffffff; padding: 2rem 3rem; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.05); text-align: center; }
          h1 { color: #ec1380; margin-top: 0; }
          .status { display: inline-block; padding: 0.5rem 1rem; margin-top: 0.5rem; border-radius: 8px; font-weight: 700; color: white; background-color: ${statusColor}; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>🚀 Backend Moda Sarita</h1>
          <p>Sistema Operativo</p>
          <div class="status">${dbStatus}</div>
        </div>
      </body>
      </html>
    `;
    res.status(err ? 500 : 200).send(htmlResponse);
  });
});

// ===== INICIAR SERVIDOR =====

// Opción 1: Para desarrollo local
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`💻 Servidor local corriendo en http://localhost:${PORT}`);
    });
}

// Opción 2: Para Vercel (IMPORTANTE)
export default app;