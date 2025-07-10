const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");
const { authenticateToken, requireEmailVerification, requireRole } = require("../middleware/auth");
const { authLimiter, passwordResetLimiter } = require("../middleware/rateLimiter");
const { validateRegistration, validateLogin, validatePasswordReset } = require("../middleware/validation");
const { pool } = require("../config/database");

// Public routes
router.post("/register", authLimiter, validateRegistration, authController.register); // yes
router.post("/login", authLimiter, validateLogin, authController.login); // yes
router.post("/refresh-token", authController.refreshToken); // yes
router.get("/verify-email", authController.verifyEmail); // yes
router.post("/resend-verification", authLimiter, authController.resendVerificationEmail); // yes
router.post("/forgot-password", passwordResetLimiter, authController.forgotPassword); // yes
router.post("/reset-password", passwordResetLimiter, validatePasswordReset, authController.resetPassword); // yes

// Protected routes
router.post("/logout", authenticateToken, authController.logout); // yes
router.post("/logout-all", authenticateToken, authController.logoutAll); // yes
router.get("/profile", authenticateToken, authController.getProfile); // yes
router.put("/profile", authenticateToken, authController.updateProfile); // yes
router.post("/change-password", authenticateToken, requireEmailVerification, authController.changePassword); // yes
router.post("/deactivate", authenticateToken, requireEmailVerification, authController.deactivateAccount); // yes
router.post("/activate", authenticateToken, authController.activateAccount);
router.post("/logout-all-users", authenticateToken, requireRole(["admin"]), authController.logoutAllUsers); // yes

router.get("/admin/users", authenticateToken, requireRole(["admin"]), async (req, res) => { // yes
  try {
    const [users] = await pool.execute(
      "SELECT id, email, first_name, last_name, is_verified, is_active, role, created_at, last_login FROM users ORDER BY created_at DESC"
    );
    res.json({ users });
  } catch (error) {
    console.error("Get users error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

module.exports = router;