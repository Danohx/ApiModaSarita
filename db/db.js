// db.js - Versión híbrida para Local y Producción
import mysql from "mysql2";
import dotenv from "dotenv";

dotenv.config();

const isProduction = process.env.NODE_ENV === "production";

const poolOptions = {
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000,
};

if (isProduction) {
  console.log("🚀 Modo Producción: Conectando via DATABASE_URL con SSL.");
  
  if (!process.env.DATABASE_URL) {
    console.error("❌ ERROR: DATABASE_URL no está definida en producción.");
  }

  poolOptions.uri = process.env.DATABASE_URL;
  poolOptions.ssl = { rejectUnauthorized: false };
} else {
  console.log("🏠 Modo Desarrollo: Conectando a MySQL local.");
  
  poolOptions.host = process.env.DB_HOST || 'localhost';
  poolOptions.user = process.env.DB_USER || 'root';
  poolOptions.password = process.env.DB_PASSWORD || '';
  poolOptions.database = process.env.DB_NAME;
}

const pool = mysql.createPool(poolOptions);

pool.getConnection((err, connection) => {
  if (err) {
    console.error(`❌ Error conectando a MySQL (${isProduction ? 'Producción' : 'Desarrollo'}):`);
    console.error(err.message);
  } else {
    console.log(`✅ Conectado a MySQL (${isProduction ? 'Producción' : 'Desarrollo'})`);
    connection.release();
  }
});

export default pool;