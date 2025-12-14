// middlaware/seguridad.js

import jwt from "jsonwebtoken";
import crypto from "crypto";
import speakeasy from "speakeasy";

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
export function authenticateJWT(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith("Bearer "))
    return res.status(401).json({ mensaje: "Token requerido" });
  try {
    const d = verifyAccessToken(h.slice(7));
    req.user = d;
    req.userId = d.id;
    next();
  } catch {
    return res.status(401).json({ mensaje: "Token inválido o expirado" });
  }
}

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