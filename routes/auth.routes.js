import { Router } from "express";
import { body, validationResult } from "express-validator"; // ✅ AÑADE ESTA IMPORTACIÓN
import {
  register,
  login,
  sendMagicLink,
  verifyMagicLink,
  verifyLogin2FA,
  requestPasswordReset,
  resetPassword,
  refreshSession, 
  logout, 
  revokeAllSessions
} from "../controllers/auth.controller.js";
import { authenticateJWT } from "../middleware/seguridad.js";

const router = Router();

// Middleware auxiliar para no repetir código
const validar = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            mensaje: "Error en los datos enviados",
            errores: errors.array() 
        });
    }
    next();
};

// ✅ AHORA SÍ: 'body' está importado correctamente
router.post("/register", [
    // 1. NOMBRE: Solo letras y espacios. Rechaza <script>, números, signos $, etc.
    body('nombre')
        .trim()
        .notEmpty().withMessage('El nombre es obligatorio')
        .matches(/^[a-zA-ZÁ-ÿ\u00f1\u00d1\s]+$/).withMessage('El nombre contiene caracteres inválidos (solo letras)'),

    // 2. APELLIDOS: Lo mismo, rechaza inyecciones SQL o scripts
    body('apellidoPaterno')
        .trim()
        .notEmpty().withMessage('El apellido es obligatorio')
        .matches(/^[a-zA-ZÁ-ÿ\u00f1\u00d1\s]+$/).withMessage('El apellido contiene caracteres inválidos'),

    // 3. CORREO: Validación estricta de formato email
    body('correo')
        .trim()
        .isEmail().withMessage('Debe ser un correo válido')
        .normalizeEmail(),
    
    // 4. CONTRASEÑA: Validación de complejidad (esto ya lo tenías, pero reforzamos)
    body('contrasena')
        .isLength({ min: 8 }).withMessage('La contraseña debe tener al menos 8 caracteres'),

    validar // <--- IMPORTANTE: Esto detiene el proceso si hay caracteres raros
], register);

// Ruta para el login de usuarios
router.post("/login", login);

// Iniciar flujo de login
router.post("/magic-link", sendMagicLink);

// Verificar el token del enlace
router.post("/magic-verify", verifyMagicLink);

// Verificar el código 2FA (si fue requerido)
router.post("/2fa-verify", verifyLogin2FA);

// Solicitar cambio (envía el correo)
router.post("/forgot-password", requestPasswordReset);

// Guardar la nueva contraseña
router.post("/reset-password", resetPassword);

// Ruta para obtener nuevo access token (Frontend la llama silenciosamente)
router.post("/refresh-token", refreshSession);

// Cerrar sesión normal
router.post("/logout", logout);

// EL REQUISITO DE LA IMAGEN: Cerrar sesión en todos los dispositivos
// Requiere authenticateJWT para saber QUÉ usuario está solicitando esto
router.post("/revoke-all", authenticateJWT, revokeAllSessions);

export default router;