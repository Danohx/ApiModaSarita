import { Router } from "express";
import {
  register,
  login,
  sendMagicLink,
  verifyMagicLink,
  verifyLogin2FA,
} from "../controllers/auth.controller.js";

const router = Router();

// Ruta para el registro de usuarios
router.post("/register", register);

// Ruta para el login de usuarios
router.post("/login", login);

// Iniciar flujo de login
router.post("/magic-link", sendMagicLink);

// Verificar el token del enlace
router.post("/magic-verify", verifyMagicLink);

// Verificar el código 2FA (si fue requerido)
router.post("/2fa-verify", verifyLogin2FA);

export default router;