const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");
const { authenticateToken, requireEmailVerification, requireRole } = require("../middleware/auth");
const { authLimiter, passwordResetLimiter } = require("../middleware/rateLimiter");
const { validateRegistration, validateLogin, validatePasswordReset } = require("../middleware/validation");
const { pool } = require("../config/database");
const cors = require("cors");
const jwt = require("jsonwebtoken");

// In your auth service
router.use(cors({
  origin: ["http://localhost:3001", "https://your-client-app.com"],
  credentials: true, // Allow cookies
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// Cookie settings for cross-domain
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "none" : "lax", // "none" for cross-site in production
  domain: ".yourdomain.com", // Set to parent domain for subdomain sharing
  maxAge: 60 * 60 * 1000
};


router.get("/authorize", authController.generateAuthCode);
router.post("/token", authController.token);
router.post("/introspect", authController.introspect);  // Token validation endpoint

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