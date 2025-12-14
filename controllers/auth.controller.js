// controllers/auth.controller.js

import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import bcrypt from "bcryptjs";
import pool from "../db/db.js"; // Necesitamos la DB
import {
  generateAccessToken,
  generateRefreshToken,
  generateTempToken,
  verifyTempToken,
  verify2FAToken,
} from "../middleware/seguridad.js";
import crypto from "crypto";

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

    // En auth.controller.js - función register
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&.#_-])[A-Za-z\d@$!%*?&.#_-]{8,}$/;

    if (!passwordRegex.test(contrasena)) {
        return res.status(400).json({ 
            mensaje: "La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un carácter especial." 
        });
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
    const refreshToken = generateRefreshToken(user.id);

    const userAgent = req.headers['user-agent'] || 'Unknown';
    const ip = req.ip;
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    
    await pool.promise().query(
      `INSERT INTO user_sessions (user_id, refresh_token, user_agent, ip_address, expires_at) 
       VALUES (?, ?, ?, ?, ?)`,
      [user.id, refreshToken, userAgent, ip, expiresAt]
    );

    res.json({
      requires2FA: false,
      accessToken: accessToken,
      refreshToken: refreshToken,
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
  if (!token) return res.status(400).json({ mensaje: "Token no proporcionado" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { correo } = decoded;

    const [users] = await pool.promise().query("SELECT id, nombre, correo, tfa_enabled FROM usuarios WHERE correo = ?", [correo]);

    if (users.length === 0) return res.status(404).json({ mensaje: "Usuario no encontrado." });

    const user = users[0];

    if (user.tfa_enabled) {
      const tempToken = generateTempToken(user.id, correo);
      res.json({
        requires2FA: true,
        tempToken: tempToken,
        mensaje: "Enlace verificado. Se requiere 2FA.",
      });
    } else {
      // 2. CORRECCIÓN: Generar Refresh Token y Guardar en BD (Igual que login)
      const accessToken = generateAccessToken(user.id, correo);
      const refreshToken = generateRefreshToken(user.id);
      
      const userAgent = req.headers['user-agent'] || 'Unknown';
      const ip = req.ip;
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

      await pool.promise().query(
        `INSERT INTO user_sessions (user_id, refresh_token, user_agent, ip_address, expires_at) VALUES (?, ?, ?, ?, ?)`,
        [user.id, refreshToken, userAgent, ip, expiresAt]
      );

      res.json({
        requires2FA: false,
        accessToken,
        refreshToken, // <--- Importante enviar esto
        user: { nombre: user.nombre, correo: user.correo },
        mensaje: "Inicio de sesión exitoso.",
      });
    }
  } catch (err) {
    res.status(401).json({ mensaje: "Enlace inválido o expirado." });
  }
};

// ===== VERIFICAR LOGIN 2FA (CORREGIDO) =====
export const verifyLogin2FA = async (req, res) => {
  const { tempToken, otpCode } = req.body;
  if (!tempToken || !otpCode) return res.status(400).json({ mensaje: "Faltan datos." });

  try {
    const decoded = verifyTempToken(tempToken);
    const { id: userId, correo } = decoded;

    // Obtenemos nombre también para enviarlo al frontend
    const sql = "SELECT id, nombre, correo, tfa_secret FROM usuarios WHERE id = ?";
    const [results] = await pool.promise().query(sql, [userId]);

    if (results.length === 0) return res.status(404).json({ mensaje: "Usuario no encontrado." });

    const user = results[0];
    const isValid = verify2FAToken(user.tfa_secret, otpCode);

    if (isValid) {
      // 3. CORRECCIÓN: Generar Refresh Token y Guardar en BD
      const accessToken = generateAccessToken(userId, correo);
      const refreshToken = generateRefreshToken(userId);

      const userAgent = req.headers['user-agent'] || 'Unknown';
      const ip = req.ip;
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

      await pool.promise().query(
        `INSERT INTO user_sessions (user_id, refresh_token, user_agent, ip_address, expires_at) VALUES (?, ?, ?, ?, ?)`,
        [userId, refreshToken, userAgent, ip, expiresAt]
      );

      res.json({
        success: true,
        accessToken,
        refreshToken, // <--- Importante
        user: { nombre: user.nombre, correo: user.correo },
        mensaje: "Inicio de sesión 2FA exitoso.",
      });
    } else {
      res.status(401).json({ success: false, mensaje: "Código 2FA inválido." });
    }
    
  } catch (err) {
    console.error("Error al verificar 2FA:", err.message);
    res.status(401).json({ mensaje: "Error al verificar el token temporal.", error: err.message });
  }
};

export const requestPasswordReset = async (req, res) => {
  const { correo } = req.body;
  
  if (!correo) return res.status(400).json({ mensaje: "Correo requerido." });

  try {
    // 1. Buscar usuario
    const [users] = await pool.promise().query("SELECT id FROM usuarios WHERE correo = ?", [correo]);

    // 🛡️ SEGURIDAD: Si no existe, NO le decimos "No existe".
    // Respondemos igual para que los hackers no sepan qué correos tienes.
    if (users.length === 0) {
      return res.json({ 
        mensaje: "Si el correo está registrado, recibirás un enlace de recuperación." 
      });
    }

    // 2. Generar token y fecha (1 hora)
    const token = crypto.randomBytes(32).toString("hex");
    const expireDate = new Date(Date.now() + 3600000); // 1 hora

    // 3. Guardar en BD
    await pool.promise().query(
      "UPDATE usuarios SET reset_token = ?, reset_expires = ? WHERE correo = ?",
      [token, expireDate, correo]
    );

    // 4. Configurar enlace y correo
    const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
    
    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });

    // ✨✨ AQUÍ ESTÁ EL DISEÑO "MODA SARITA" ADAPTADO ✨✨
    await transporter.sendMail({
      from: `Moda Sarita <${process.env.EMAIL_USER}>`,
      to: correo,
      subject: "🔑 Restablecer tu contraseña - Moda Sarita",
      html: `
        <div style="font-family: 'Manrope', Arial, sans-serif; max-width: 600px; margin: 20px auto; border: 1px solid #eee; border-radius: 16px; overflow: hidden;">
          
          <div style="background-color: #f8f6f7; padding: 30px; text-align: center;">
            <h1 style="color: #221019; margin: 0; font-size: 24px;">Solicitud de cambio de</h1>
            <h2 style="color: #ec1380; margin: 5px 0 0; font-size: 36px; font-weight: 800;">Contraseña</h2>
          </div>

          <div style="padding: 30px 40px; background-color: #ffffff;">
            <p style="font-size: 18px; color: #221019; margin-top: 0;">Hola,</p>
            
            <p style="font-size: 18px; color: #333; line-height: 1.6;">
              Hemos recibido una solicitud para restablecer la contraseña de tu cuenta en <strong>Moda Sarita</strong>.
              <br><br>
              Si fuiste tú, haz clic en el botón de abajo para crear una nueva contraseña segura.
            </p>
            
            <div style="text-align: center; margin: 40px 0;">
              <a href="${resetLink}" 
                style="background-color: #ec1380; 
                        color: #ffffff; 
                        padding: 18px 35px; 
                        text-decoration: none; 
                        border-radius: 12px; 
                        font-weight: 700; 
                        font-size: 18px;
                        display: inline-block;">
                Cambiar Contraseña
              </a>
            </div>
            
            <p style="font-size: 16px; color: #555; line-height: 1.6;">
              <strong>⚠️ Seguridad:</strong> Este enlace expira en <strong>1 hora</strong>.
              <br>
              Si no realizaste esta solicitud, tu cuenta sigue segura y no necesitas hacer nada.
            </p>
          </div>

          <div style="background-color: #f8f6f7; padding: 25px; border-top: 1px solid #eee;">
            <p style="font-size: 12px; color: #888; margin: 0; text-align: center;">
              Enviado automáticamente por el sistema de seguridad de Moda Sarita.
            </p>
          </div>
        </div>
      `,
    });

    res.json({ mensaje: "Si el correo está registrado, recibirás un enlace de recuperación." });

  } catch (error) {
    console.error(error);
    res.status(500).json({ mensaje: "Error interno." });
  }
};

// 2. CAMBIAR LA CONTRASEÑA (Recibir token y nueva pass)
export const resetPassword = async (req, res) => {
  const { token, nuevaContrasena } = req.body;

  if (!token || !nuevaContrasena) {
    return res.status(400).json({ mensaje: "Faltan datos." });
  }

  // VALIDACIÓN DE COMPLEJIDAD (Reutiliza tu regex aquí)
  // Cumple con: "Probar crear contraseñas simples... El sistema debe rechazarlas" [Fuente: 1]
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  if (!passwordRegex.test(nuevaContrasena)) {
      return res.status(400).json({ 
          mensaje: "La contraseña no cumple con los requisitos de seguridad." 
      });
  }

  try {
    // Buscar usuario con ese token Y que no haya expirado
    const [users] = await pool.promise().query(
      "SELECT id FROM usuarios WHERE reset_token = ? AND reset_expires > NOW()", 
      [token]
    );

    if (users.length === 0) {
      // Aquí sí podemos decir que el token es inválido o expiró [Fuente: 1]
      return res.status(400).json({ mensaje: "Enlace inválido o expirado." });
    }

    const user = users[0];

    // Hashear nueva contraseña
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(nuevaContrasena, salt);

    // Actualizar usuario y BORRAR el token (para que no se use 2 veces)
    await pool.promise().query(
      "UPDATE usuarios SET contrasena = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?",
      [hash, user.id]
    );

    res.json({ mensaje: "Contraseña actualizada exitosamente. Ya puedes iniciar sesión." });

  } catch (error) {
    console.error(error);
    res.status(500).json({ mensaje: "Error al actualizar contraseña." });
  }
};

export const refreshSession = async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ mensaje: "Token requerido" });

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET || "secreto_super_seguro_refresh");

    // Verificar en BD
    const [sessions] = await pool.promise().query("SELECT * FROM user_sessions WHERE refresh_token = ?", [refreshToken]);
    if (sessions.length === 0) return res.status(403).json({ mensaje: "Sesión inválida o revocada." });

    const [users] = await pool.promise().query("SELECT id, correo FROM usuarios WHERE id = ?", [decoded.id]);
    if (users.length === 0) return res.status(403).json({ mensaje: "Usuario no existe" });
    
    const accessToken = generateAccessToken(users[0].id, users[0].correo);
    res.json({ accessToken });

  } catch (error) {
    return res.status(403).json({ mensaje: "Token inválido o expirado" });
  }
};

export const logout = async (req, res) => {
  const { refreshToken } = req.body;
  
  // Borramos solo ESTA sesión de la base de datos
  await pool.promise().query("DELETE FROM user_sessions WHERE refresh_token = ?", [refreshToken]);
  
  res.sendStatus(204);
};

export const revokeAllSessions = async (req, res) => {
  const userId = req.user.id; // Viene del middleware authenticateJWT

  try {
    // BORRA TODAS las sesiones de este usuario en la tabla
    await pool.promise().query("DELETE FROM user_sessions WHERE user_id = ?", [userId]);
    
    res.json({ mensaje: "Se han cerrado todas las sesiones en todos los dispositivos." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ mensaje: "Error al revocar sesiones." });
  }
};