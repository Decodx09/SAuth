const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const session = require("express-session"); // ADD THIS IMPORT
require("dotenv").config();
const jwt = require("jsonwebtoken");
const token = require("./models/Token");

const { initDatabase } = require("./config/database");
const authRoutes = require("./routes/auth");
const { generalLimiter } = require("./middleware/rateLimiter");

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: ["http://localhost:3001", "http://localhost:3000"], 
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// Rate limiting
app.use(generalLimiter);

// Body parsing middleware
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// ADD SESSION MIDDLEWARE HERE - BEFORE YOUR ROUTES
app.use(session({
  secret: process.env.SESSION_SECRET || "your-oauth-server-session-secret-change-in-production",
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === "production", // true in production with HTTPS
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true,
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax"
  }
}));

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

  try {
      // 2. Verify the token using your REFRESH_TOKEN_SECRET
      const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
      
      // 3. If valid, create a new access token
      const newAccessToken = jwt.sign(
          { userId: decoded.userId, role: decoded.role },
          process.env.ACCESS_TOKEN_SECRET,
          { expiresIn: "15m" }
      );

      // 4. Send the new access token to the client
      res.json({ accessToken: newAccessToken });

  } catch (err) {
      return res.status(403).json({ message: "Invalid or expired refresh token." });
  }
});

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