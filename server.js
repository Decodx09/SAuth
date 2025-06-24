const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
require("dotenv").config();
const jwt = require("jsonwebtoken");

const { initDatabase } = require("./config/database");
const authRoutes = require("./routes/auth");
const { generalLimiter } = require("./middleware/rateLimiter");

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true
}));

// Rate limiting
app.use(generalLimiter);

// Body parsing middleware
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// Trust proxy for accurate IP addresses
app.set("trust proxy", 1);

// Routes
app.use("/api/auth", authRoutes);

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({ status: "OK", timestamp: new Date().toISOString() });
});

app.post("/api/auth/refresh", async (req, res) => {
    
  // 1. Get the refresh token from the HttpOnly cookie
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
      return res.status(401).json({ message: "No refresh token provided." });
  }

  // You should also have a check here to see if the refresh token is in your database
  // and has not been revoked. For example:
  // const tokenInDb = await User.findOne({ refreshToken: refreshToken });
  // if (!tokenInDb) return res.status(403).json({ message: 'Forbidden.' });

  try {
      // 2. Verify the token using your REFRESH_TOKEN_SECRET
      const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
      
      // 3. If valid, create a new access token
      const newAccessToken = jwt.sign(
          { userId: decoded.userId, role: decoded.role }, // Payload
          process.env.ACCESS_TOKEN_SECRET,               // Secret Key
          { expiresIn: "15m" }                           // Expiration
      );

      // 4. Send the new access token to the client
      res.json({ accessToken: newAccessToken });

  } catch (err) {;
      // If verification fails (expired, invalid signature, etc.)
      return res.status(403).json({ message: "Invalid or expired refresh token." });
  }
});

// // When a user logs in successfully...
// res.cookie('refreshToken', newRefreshToken, {
//   httpOnly: true,                 // Cannot be accessed by JS
//   secure: true,                   // Only sent over HTTPS
//   sameSite: 'strict',             // Mitigates CSRF attacks
//   maxAge: 30 * 24 * 60 * 60 * 1000  // 30 days
// });

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ message: "Internal server error" });
});

// 404 handler
app.use("*", (req, res) => {
  res.status(404).json({ message: "Route not found" });
});

// Initialize database and start server
const startServer = async () => {
  try {
    await initDatabase();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Email service configured for ${process.env.EMAIL_HOST}`);
      console.log(`CORS enabled for ${process.env.FRONTEND_URL || "http://localhost:3000"}`);
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
};

startServer();