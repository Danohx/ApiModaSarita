// ===== LIBRERÍAS =====
import express from "express";
import dotenv from "dotenv";
import cors from 'cors';
import pool from "./db/db.js";
import rateLimit from 'express-rate-limit';
import helmet from "helmet";

// --- 1. CONFIGURAR DOTENV PRIMERO ---
// Esto debe ir ANTES de usar process.env
dotenv.config(); 

// ===== IMPORTAR RUTAS =====
import authRoutes from "./routes/auth.routes.js";
import securityRoutes from "./routes/security.routes.js";

// --- 2. DEFINIR ORÍGENES ---
// Agregamos la URL explícita por seguridad y la variable de entorno
const allowedOrigins = [
  "https://frontend-moda-sarita.vercel.app", // <--- TU URL EXACTA
  "http://localhost:5173", // <--- PARA TUS PRUEBAS LOCALES
  process.env.FRONTEND_URL
];

// Configuración del Rate Limit (Límite de intentos)
const loginLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, 
    max: 3, 
    message: { 
        mensaje: "⛔ Demasiados intentos. Por seguridad, espera 5 minutos." 
    },
    standardHeaders: true, 
    skipSuccessfulRequests: true,
    legacyHeaders: false,
    keyGenerator: (req, res) => {
        if (req.body && req.body.correo) {
            return req.body.correo; 
        }
        return req.ip; 
    }
});

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';

app.set('trust proxy', 1);

// ===== MIDDLEWARES =====
app.use(helmet());
app.use((req, res, next) => {
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  next();
});
app.use(express.json());

// 3. Configuración de CORS ARREGLADA
app.use(cors({
  origin: function (origin, callback) {
    // Permitir solicitudes sin origen (como Postman o Mobile Apps)
    if (!origin) return callback(null, true);
    
    // Verificar si el origen está en la lista permitida
    if (allowedOrigins.indexOf(origin) === -1) {
      // Tip de depuración: Imprime qué origen está intentando entrar si falla
      console.log("Bloqueado por CORS:", origin); 
      const msg = 'La política CORS de este sitio no permite acceso desde el origen especificado.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true, 
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
  allowedHeaders: "Content-Type,Authorization"
}));

// ===== DEFINICIÓN DE RUTAS =====
app.use("/api/auth/login", loginLimiter);
app.use("/api/auth/2fa-verify", loginLimiter);
app.use("/api/auth/forgot-password", loginLimiter);
app.use("/api/auth", authRoutes);
app.use("/api/security", securityRoutes);

// Health Check
app.get("/", (req, res) => {
  pool.query('SELECT 1 + 1 AS result', (err, results) => {
    let dbStatus = err ? "Base de Datos: Desconectada" : "Base de Datos: Conectada";
    let statusColor = err ? "#c62828" : "#2e7d32";
    
    const htmlResponse = `
      <html lang="es">
      <head>
        <title>Estado del Servidor</title>
        <style>
          body { font-family: sans-serif; display: grid; place-items: center; min-height: 90vh; background-color: #f8f6f7; }
          .container { background-color: white; padding: 2rem; border-radius: 12px; text-align: center; box-shadow: 0 10px 30px rgba(0,0,0,0.05); }
          .status { padding: 0.5rem 1rem; border-radius: 8px; color: white; background-color: ${statusColor}; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1 style="color: #ec1380;">🚀 Backend de Autenticación</h1>
          <div class="status">${dbStatus}</div>
        </div>
      </body>
      </html>
    `;
    res.status(err ? 500 : 200).send(htmlResponse);
  });
});

// ===== INICIAR SERVIDOR =====
app.listen(PORT, HOST, () => {
  console.log(`Servidor corriendo en http://${HOST}:${PORT}`);
  console.log(`Orígenes permitidos:`, allowedOrigins); // Para que veas en logs si cargó bien
});