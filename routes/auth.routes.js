import { Router } from "express";
import {
  register,
  login,
  sendMagicLink,
  verifyMagicLink,
  verifyLogin2FA,
  requestPasswordReset,
    resetPassword
} from "../controllers/auth.controller.js";

const router = Router();

// Middleware auxiliar para no repetir código
const validar = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
};

router.post("/register", [
    // Validamos y limpiamos (Sanitización)
    body('nombre').trim().escape(),
    body('apellidoPaterno').trim().escape(),
    body('correo').isEmail().normalizeEmail(),
    validar
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

export default router;