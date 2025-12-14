// middlaware/seguridad.js

import jwt from "jsonwebtoken";
import crypto from "crypto";
import speakeasy from "speakeasy";
import pool from "../db/db.js";

// ===== 1. GESTIÓN DE TOKENS DE ACCESO (JWT) =====
export function generateAccessToken(userId, email) {
  return jwt.sign({ id: userId, correo: email }, process.env.JWT_SECRET, {
    expiresIn: "15m",
  });
}

export function verifyAccessToken(token) {
  return jwt.verify(token, process.env.JWT_SECRET);
}

// ===== 2. GESTIÓN DE SESIONES DE USUARIO =====
export function createSession(userId, authMethod = "magiclink") {
  const sessionId = crypto.randomBytes(16).toString("hex");
  const now = Date.now();
  activeSessions.set(sessionId, {
    userId,
    authMethod,
    createdAt: now,
    lastActivity: now,
  });
  return sessionId;
}

// ... (Aquí irían closeSession y getUserActiveSessions si los necesitas)

// ===== 3. MIDDLEWARE DE AUTENTICACIÓN JWT =====
export const authenticateJWT = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(' ')[1];

    jwt.verify(token, process.env.JWT_SECRET, async (err, user) => {
      if (err) {
        return res.status(403).json({ mensaje: "Token inválido o expirado" });
      }

      try {
        const [sessions] = await pool.promise().query(
          "SELECT id FROM user_sessions WHERE user_id = ? LIMIT 1", 
          [user.id]
        );

        if (sessions.length === 0)
           return res.status(401).json({ mensaje: "Sesión revocada remotamente." });

        req.user = user;
        req.userId = user.id;
        next();

      } catch (dbError) {
        console.error(dbError);
        return res.status(500).json({ mensaje: "Error verificando sesión." });
      }
    });
  } else {
    res.sendStatus(401);
  }
};

// ===== 4. LÓGICA DE DOBLE FACTOR (2FA) =====
export function generateTempToken(userId, email) {
  return jwt.sign(
    { id: userId, correo: email, tfa_pending: true },
    process.env.JWT_SECRET,
    { expiresIn: "5m" }
  );
}

export function verifyTempToken(token) {
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  if (!decoded.tfa_pending) throw new Error("Token no válido para 2FA");
  return decoded;
}

export function generate2FASecret(email) {
  const secret = speakeasy.generateSecret({
    name: `ModaSarita (${email})`,
  });
  return {
    base32: secret.base32,
    otpauth_url: secret.otpauth_url,
  };
}

export function verify2FAToken(secret, token) {
  return speakeasy.totp.verify({
    secret: secret,
    encoding: "base32",
    token: token,
    window: 1,
  });
}

export function generateRefreshToken(userId) {
  return jwt.sign({ id: userId }, process.env.REFRESH_SECRET || "secreto_super_seguro_refresh", {
    expiresIn: "7d",
  });
}