import pool from "../db/db.js";
import { generate2FASecret, verify2FAToken } from "../middleware/seguridad.js";

// Función para mostrar el QR y guardar el secreto temporalmente
export const setup2FA = (req, res) => {
    const { correo: email } = req.user;
    const { base32, otpauth_url } = generate2FASecret(email);

    const sql = "UPDATE usuarios SET tfa_secret = ?, tfa_enabled = 0 WHERE correo = ?";
    pool.query(sql, [base32, email], (err, result) => {
        if (err)
            return res.status(500).json({ mensaje: "Error al guardar secreto en DB" });
        
        res.json({ otpauth_url });
    });
};

// Función para verificar el primer token y habilitar 2FA permanentemente
export const enable2FA = (req, res) => {
    const { token } = req.body;
    const { correo: email } = req.user;

    const sql = "SELECT tfa_secret FROM usuarios WHERE correo = ?";
    pool.query(sql, [email], (err, results) => {
        if (err || results.length === 0)
            return res.status(404).json({ mensaje: "Usuario no encontrado" });

        const { tfa_secret } = results[0];
        if (!tfa_secret)
            return res.status(400).json({ mensaje: "Llama a /2fa/setup primero" });

        const verified = verify2FAToken(tfa_secret, token);

        if (verified) {
            const updateSql = "UPDATE usuarios SET tfa_enabled = 1 WHERE correo = ?";
            pool.query(updateSql, [email], (updateErr) => {
                if (updateErr)
                    return res.status(500).json({ mensaje: "Error al habilitar 2FA en DB" });
                
                res.json({ success: true, message: "2FA habilitado correctamente." });
            });
        } else {
            res.status(401).json({ success: false, message: "Código OTP inválido." });
        }
    });
};