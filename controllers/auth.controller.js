// controllers/auth.controller.js

import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import bcrypt from "bcryptjs";
import pool from "../db/db.js"; // Necesitamos la DB
import {
  generateAccessToken,
  createSession,
  generateTempToken,
  verifyTempToken,
  verify2FAToken,
} from "../middleware/seguridad.js";

export const register = async (req, res) => {
  // 1. Destructuramos TODOS los campos del body
  const {
    nombre,
    apellidoPaterno,
    apellidoMaterno,
    telefono,
    edad,
    correo,
    contrasena,
  } = req.body

  // 2. Validación básica
  if (!nombre || !apellidoPaterno || !correo || !contrasena) {
    return res
      .status(400)
      .json({
        mensaje: 'Nombre, Apellido Paterno, Correo y Contraseña son requeridos.',
      })
  }

  try {
    // 3. Verificar si el usuario ya existe
    const [users] = await pool
      .promise()
      .query('SELECT id FROM usuarios WHERE correo = ?', [correo])

    if (users.length > 0) {
      return res.status(409).json({ mensaje: 'El correo ya está registrado.' })
    }

    // 4. Hashear la contraseña
    const salt = await bcrypt.genSalt(10)
    const contrasenaHash = await bcrypt.hash(contrasena, salt)

    // 5. Insertar el nuevo usuario en la BD (¡con todas las columnas!)
    const sql = `
      INSERT INTO usuarios 
        (nombre, apellido_paterno, apellido_materno, telefono, edad, correo, contrasena, tfa_enabled) 
      VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    `
    const [result] = await pool
      .promise()
      .query(sql, [
        nombre,
        apellidoPaterno,
        apellidoMaterno,
        telefono,
        edad,
        correo,
        contrasenaHash,
      ])

    res
      .status(201)
      .json({
        mensaje: 'Usuario registrado exitosamente.',
        userId: result.insertId,
      })
  } catch (error) {
    console.error('Error en el registro:', error)
    res.status(500).json({ mensaje: 'Error interno del servidor.' })
  }
}

export const login = async (req, res) => {
  const { correo, contrasena } = req.body;
  if (!correo || !contrasena) {
    return res
      .status(400)
      .json({ mensaje: "Correo y contraseña son requeridos." });
  }

  try {
    // 1. Buscar al usuario
    const [users] = await pool
      .promise()
      .query(
        "SELECT id, correo, contrasena, tfa_enabled, tfa_secret FROM usuarios WHERE correo = ?",
        [correo]
      );

    if (users.length === 0) {
      return res.status(401).json({ mensaje: "Credenciales inválidas." });
    }

    const user = users[0];

    // 2. Comparar la contraseña
    const isMatch = await bcrypt.compare(contrasena, user.contrasena);
    if (!isMatch) {
      return res.status(401).json({ mensaje: "Credenciales inválidas." });
    }

    // 3. Revisar si tiene 2FA activado (¡CONECTAMOS CON EL FLUJO ANTIGUO!)
    if (user.tfa_enabled) {
      // SÍ TIENE 2FA: Generar un token temporal
      const tempToken = generateTempToken(user.id, user.correo);
      return res.json({
        requires2FA: true,
        tempToken: tempToken,
        mensaje: "Credenciales válidas. Se requiere 2FA.",
      });
    }

    // 4. NO TIENE 2FA: Iniciar sesión directamente
    const accessToken = generateAccessToken(user.id, user.correo);
    const sessionId = createSession(user.id, "contrasena");

    res.json({
      requires2FA: false,
      accessToken: accessToken,
      sessionId: sessionId,
      mensaje: "Inicio de sesión exitoso.",
    });
  } catch (error) {
    console.error("Error en el login:", error);
    res.status(500).json({ mensaje: "Error interno del servidor." });
  }
};

export const sendMagicLink = async (req, res) => {
  const { correo } = req.body;
  if (!correo)
    return res.status(400).json({ mensaje: "Debes ingresar un correo." });

  try {
    const [users] = await pool
      .promise()
      .query("SELECT id FROM usuarios WHERE correo = ?", [correo]);

    if (users.length === 0)
      return res.status(404).json({ mensaje: "Usuario no encontrado." });

    const token = jwt.sign({ correo }, process.env.JWT_SECRET, {
      expiresIn: "5m",
    });
    const enlace = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/magic-verify/${token}`;

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });

    await transporter.sendMail({
      from: `Moda Sarita <${process.env.EMAIL_USER}>`,
      to: correo,
      subject: "🛍️ Tu acceso directo a Moda Sarita",
      html: `
        <div style="font-family: 'Manrope', Arial, sans-serif; max-width: 600px; margin: 20px auto; border: 1px solid #eee; border-radius: 16px; overflow: hidden;">
          
          <div style="background-color: #f8f6f7; padding: 30px; text-align: center;">
            <h1 style="color: #221019; margin: 0; font-size: 24px;">Bienvenida de nuevo a</h1>
            <h2 style="color: #ec1380; margin: 5px 0 0; font-size: 36px; font-weight: 800;">Moda Sarita</h2>
          </div>

          <div style="padding: 30px 40px; background-color: #ffffff;">
            <p style="font-size: 18px; color: #221019; margin-top: 0;">Hola,</p>
            
            <p style="font-size: 18px; color: #333; line-height: 1.6;">
              Tu acceso exclusivo está listo. Haz clic en el botón de abajo para ingresar de forma segura a tu cuenta.
            </p>
            
            <div style="text-align: center; margin: 40px 0;">
              <a href="${enlace}" 
                style="background-color: #ec1380; 
                        color: #ffffff; 
                        padding: 18px 35px; 
                        text-decoration: none; 
                        border-radius: 12px; 
                        font-weight: 700; 
                        font-size: 18px;
                        display: inline-block;">
                Iniciar sesión
              </a>
            </div>
            
            <p style="font-size: 16px; color: #555; line-height: 1.6;">
              <strong>⚠️ Importante:</strong> Este enlace es personal e intransferible.
              <br>
              Por seguridad, caduca en <strong>5 minutos</strong>.
            </p>
          </div>

          <div style="background-color: #f8f6f7; padding: 25px; border-top: 1px solid #eee;">
            <p style="font-size: 12px; color: #888; margin: 0; text-align: center;">
              Si no solicitaste este acceso, por favor ignora este mensaje.
            </p>
          </div>
        </div>
      `,
    });
    res.json({ mensaje: "¡Enlace mágico enviado! Revisa tu correo." });
  } catch (error) {
    console.error("Error al enviar el enlace mágico:", error);
    res.status(500).json({ mensaje: "Error al enviar el enlace mágico." });
  }
};

// ===== VERIFICAR ENLACE MÁGICO =====

export const verifyMagicLink = async (req, res) => {
  const { token } = req.body;
  if (!token)
    return res.status(400).json({ mensaje: "Token no proporcionado" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { correo } = decoded;

    // 1. Buscar al usuario en la BD (con await)
    const [users] = await pool
      .promise()
      .query("SELECT id, tfa_enabled FROM usuarios WHERE correo = ?", [correo]);

    if (users.length === 0)
      return res.status(404).json({ mensaje: "Usuario no encontrado." });

    const user = users[0];

    // 2. Revisar si tiene 2FA activado
    if (user.tfa_enabled) {
      const tempToken = generateTempToken(user.id, correo);
      res.json({
        requires2FA: true,
        tempToken: tempToken,
        mensaje: "Enlace verificado. Se requiere 2FA.",
      });
    } else {
      const accessToken = generateAccessToken(user.id, correo);
      const sessionId = createSession(user.id, "magiclink");

      res.json({
        requires2FA: false,
        accessToken: accessToken,
        sessionId: sessionId,
        mensaje: "Inicio de sesión exitoso.",
      });
    }
  } catch (err) {
    res.status(401).json({ mensaje: "Enlace inválido o expirado." });
  }
};

// ---- ¡NUEVA FUNCIÓN NECESARIA! ----
// Función para verificar el código 2FA durante el login
export const verifyLogin2FA = async (req, res) => {
  const { tempToken, otpCode } = req.body;
  if (!tempToken || !otpCode)
    return res.status(400).json({ mensaje: "Faltan datos." });

  try {
    // 1. Verificar el token temporal
    const decoded = verifyTempToken(tempToken);
    const { id: userId, correo } = decoded;

    // 2. Obtener el secreto 2FA del usuario
    const sql = "SELECT tfa_secret FROM usuarios WHERE id = ?";
    
    // (Asegúrate de que tu lógica de BD esté aquí...)
    // Voy a asumir que estás usando la versión con Promesas que te mostré:
    const [results] = await pool.promise().query(sql, [userId]);

    if (results.length === 0)
      return res.status(404).json({ mensaje: "Usuario no encontrado." });

    const { tfa_secret } = results[0];
    const isValid = verify2FAToken(tfa_secret, otpCode);

    if (isValid) {
      // 3. Código VÁLIDO: Iniciar sesión
      const accessToken = generateAccessToken(userId, correo);
      const sessionId = createSession(userId, "magiclink_2fa");

      res.json({
        success: true,
        accessToken: accessToken,
        sessionId: sessionId,
        mensaje: "Inicio de sesión 2FA exitoso.",
      });
    } else {
      // 4. Código INVÁLIDO
      res.status(401).json({ success: false, mensaje: "Código 2FA inválido." });
    }
    
  } catch (err) {
    // --- ¡BLOQUE MEJORADO! ---
    console.error("Error al verificar 2FA:", err.message); // <-- Para tu terminal
    
    // Envía el error real a Postman
    res.status(401).json({ 
        mensaje: "Error al verificar el token temporal.",
        error: err.message 
    });
  }
};