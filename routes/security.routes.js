import { Router } from "express";
import { setup2FA, enable2FA } from "../controllers/security.controller.js";
import { authenticateJWT } from "../middleware/seguridad.js";

const router = Router();

// Estas rutas SÍ deben estar protegidas,
// solo un usuario logueado puede configurar su 2FA.

// POST /security/2fa/setup
router.post("/2fa/setup", authenticateJWT, setup2FA);

// POST /security/2fa/enable
router.post("/2fa/enable", authenticateJWT, enable2FA);

export default router;