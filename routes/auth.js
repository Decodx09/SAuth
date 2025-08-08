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

// Add this GET route to your routes/auth.js file
router.get("/login", (req, res) => {
  const { oauth } = req.query;
  
  if (oauth === "true") {
    // Check if theres a stored OAuth request in session
    const oauthRequest = req.session?.oauthRequest;
    
    if (oauthRequest) {
      res.send(`
        <h1>Authorize Application</h1>
        <p><strong>Client Application</strong> wants to access your account.</p>
        <p><strong>Redirect URI:</strong> ${oauthRequest.redirect_uri}</p>
        <p><strong>Requested Scopes:</strong> read, write, profile</p>
        
        <div style="margin: 20px 0; padding: 20px; border: 1px solid #ddd;">
          <h3>Please log in to continue:</h3>
          <form method="POST" action="/api/auth/login" style="margin-bottom: 20px;">
            <div style="margin: 10px 0;">
              <label>Email:</label><br>
              <input type="email" name="email" required style="width: 300px; padding: 5px;">
            </div>
            <div style="margin: 10px 0;">
              <label>Password:</label><br>
              <input type="password" name="password" required style="width: 300px; padding: 5px;">
            </div>
            <input type="hidden" name="oauth_flow" value="true">
            <button type="submit" style="padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer;">
              Login & Authorize
            </button>
          </form>
        </div>
        
        <p><a href="${oauthRequest.redirect_uri}?error=access_denied&state=${oauthRequest.state || ""}">Cancel Authorization</a></p>
      `);
    } else {
      res.status(400).send(`
        <h1>Invalid OAuth Request</h1>
        <p>No OAuth request found in session. Please start the authorization flow again.</p>
        <p><a href="http://localhost:3001">Go back to client app</a></p>
      `);
    }
  } else {
    // Regular login page (non-OAuth)
    res.send(`
      <h1>OAuth Server Login</h1>
      <form method="POST" action="/api/auth/login">
        <div style="margin: 10px 0;">
          <label>Email:</label><br>
          <input type="email" name="email" required style="width: 300px; padding: 5px;">
        </div>
        <div style="margin: 10px 0;">
          <label>Password:</label><br>
          <input type="password" name="password" required style="width: 300px; padding: 5px;">
        </div>
        <button type="submit" style="padding: 10px 20px; background: #28a745; color: white; border: none; cursor: pointer;">
          Login
        </button>
      </form>
    `);
  }
});


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