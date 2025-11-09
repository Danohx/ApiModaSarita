// ===== LIBRERÍAS =====
import express from "express";
import dotenv from "dotenv";
import cors from 'cors'
import pool from "./db/db.js";

// ===== IMPORTAR RUTAS =====
import authRoutes from "./routes/auth.routes.js";
import securityRoutes from "./routes/security.routes.js";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 4000 || 3000;

// ===== MIDDLEWARES =====
app.use(express.json());

// 2. Configuración de CORS segura para producción
const frontendURL = process.env.FRONTEND_URL || "http://localhost:5173";
app.use(cors({
  origin: frontendURL
}));

// ===== DEFINICIÓN DE RUTAS =====
app.use("/api/auth", authRoutes);
app.use("/api/security", securityRoutes);

app.get("/", (req, res) => {
  pool.query('SELECT 1 + 1 AS result', (err, results) => {
    
    let dbStatus = "";
    let statusColor = "";

    if (err) {
      console.error("❌ Health check (en /) - Error DB:", err.message);
      dbStatus = "Base de Datos: Desconectada";
      statusColor = "#c62828";
    } else {
      console.log("✅ Health check (en /) - DB Conectada");
      dbStatus = "Base de Datos: Conectada";
      statusColor = "#2e7d32";
    }

    const htmlResponse = `
      <html lang="es">
      <head>
        <meta charset="UTF-8">
        <title>Estado del Servidor</title>
        <style>
          body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
            display: grid; 
            place-items: center; 
            min-height: 90vh; 
            background-color: #f8f6f7; 
            color: #221019;
          }
          .container { 
            background-color: #ffffff; 
            padding: 2rem 3rem; 
            border-radius: 12px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.05); 
            text-align: center; 
          }
          h1 { color: #ec1380; margin-top: 0; }
          .status { 
            display: inline-block; 
            padding: 0.5rem 1rem; 
            margin-top: 0.5rem;
            border-radius: 8px; 
            font-weight: 700; 
            color: white; 
            background-color: ${statusColor};
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>🚀 Backend de Autenticación</h1>
          <p>¡El servidor de Moda Sarita está funcionando!</p>
          <div class="status">
            ${dbStatus}
          </div>
        </div>
      </body>
      </html>
    `;
    
    res.status(err ? 500 : 200).send(htmlResponse);
  });
});

// ===== INICIAR SERVIDOR =====
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
