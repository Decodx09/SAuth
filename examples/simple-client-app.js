const express = require("express");
const session = require("express-session");
const fetch = require("node-fetch");

const app = express();
const PORT = 3001;

// Essential middleware - MUST be before session configuration
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Improved session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || "your-strong-session-secret-change-in-production",
  resave: false,
  saveUninitialized: false, // Changed to false for better security
  cookie: { 
    secure: false, // Set to true in production with HTTPS
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true // Prevent XSS attacks
  }
}));

// OAuth configuration with environment variable support
const OAUTH_CONFIG = {
  authUrl: process.env.OAUTH_AUTH_URL || "http://localhost:3000/api/auth/authorize",
  tokenUrl: process.env.OAUTH_TOKEN_URL || "http://localhost:3000/api/auth/token",
  validateUrl: process.env.OAUTH_VALIDATE_URL || "http://localhost:3000/api/auth/validate",
  clientId: process.env.OAUTH_CLIENT_ID || "your-client-app-id", // Update this
  clientSecret: process.env.OAUTH_CLIENT_SECRET || "your-client-secret", // Update this
  redirectUri: process.env.OAUTH_REDIRECT_URI || "http://localhost:3001/auth/callback"
};

// Validation function for OAuth config
function validateOAuthConfig() {
  const required = ["clientId", "clientSecret"];
  const missing = required.filter(key => 
    !OAUTH_CONFIG[key] || OAUTH_CONFIG[key].includes("your-")
  );
  
  if (missing.length > 0) {
    console.warn(`⚠️  Warning: Please configure these OAuth settings: ${missing.join(", ")}`);
  }
}

// Home page
app.get("/", (req, res) => {
  if (req.session && req.session.user) {
    res.send(`
      <h1>Welcome, ${req.session.user.name || "User"}!</h1>
      <p>You are logged in via OAuth.</p>
      <p><strong>User Info:</strong></p>
      <pre>${JSON.stringify(req.session.user, null, 2)}</pre>
      <p><a href="/profile">View Profile</a></p>
      <p><a href="/logout">Logout</a></p>
    `);
  } else {
    res.send(`
      <h1>OAuth Client Example</h1>
      <p>This is a demo client application that integrates with your OAuth server.</p>
      <p><a href="/login">Login with OAuth</a></p>
    `);
  }
});

// Initiate OAuth login
app.get("/login", (req, res) => {
  // Check if session is available
  if (!req.session) {
    return res.status(500).send("Session not available. Please check server configuration.");
  }

  // Generate cryptographically secure random state
  const state = require("crypto").randomBytes(16).toString("hex");
  req.session.oauthState = state;
  
  // Build authorization URL
  const authUrl = new URL(OAUTH_CONFIG.authUrl);
  authUrl.searchParams.append("response_type", "code");
  authUrl.searchParams.append("client_id", OAUTH_CONFIG.clientId);
  authUrl.searchParams.append("redirect_uri", OAUTH_CONFIG.redirectUri);
  authUrl.searchParams.append("scope", "read write profile");
  authUrl.searchParams.append("state", state);
  
  console.log("Redirecting to:", authUrl.toString());
  res.redirect(authUrl.toString());
});

// OAuth callback handler with improved error handling
app.get("/auth/callback", async (req, res) => {
  const { code, state, error } = req.query;
  
  // Check session availability
  if (!req.session) {
    return res.status(500).send("Session not available");
  }
  
  // Handle OAuth errors
  if (error) {
    console.error("OAuth error received:", error);
    return res.status(400).send(`OAuth Error: ${error}`);
  }
  
  // Verify state parameter to prevent CSRF
  if (!state || state !== req.session.oauthState) {
    console.error("Invalid state parameter");
    return res.status(400).send("Invalid state parameter - possible CSRF attack");
  }
  
  if (!code) {
    return res.status(400).send("No authorization code received");
  }
  
  try {
    console.log("Exchanging code for tokens...");
    
    // Exchange authorization code for access token
    const tokenResponse = await fetch(OAUTH_CONFIG.tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code: code,
        client_id: OAUTH_CONFIG.clientId,
        client_secret: OAUTH_CONFIG.clientSecret,
        redirect_uri: OAUTH_CONFIG.redirectUri
      })
    });
    
    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      console.error("Token exchange failed:", errorText);
      return res.status(400).send(`Token exchange failed: ${errorText}`);
    }
    
    const tokenData = await tokenResponse.json();
    console.log("Token exchange successful");
    
    // Validate token response structure
    if (!tokenData.access_token) {
      console.error("Invalid token response - missing access_token");
      return res.status(500).send("Invalid response from OAuth server");
    }
    
    // Store tokens in session
    req.session.accessToken = tokenData.access_token;
    if (tokenData.refresh_token) {
      req.session.refreshToken = tokenData.refresh_token;
    }
    
    // Store user info safely (handle missing user data gracefully)
    if (tokenData.user) {
      req.session.user = {
        id: tokenData.user.id,
        email: tokenData.user.email,
        name: tokenData.user.firstName && tokenData.user.lastName 
          ? `${tokenData.user.firstName} ${tokenData.user.lastName}`.trim()
          : tokenData.user.name || tokenData.user.email || "User",
        role: tokenData.user.role,
        isVerified: tokenData.user.isVerified
      };
    } else {
      // Fallback if user data is not included in token response
      req.session.user = {
        id: "unknown",
        email: "unknown",
        name: "User",
        role: "user",
        isVerified: false
      };
    }
    
    // Clear OAuth state
    delete req.session.oauthState;
    
    res.redirect("/");
  } catch (error) {
    console.error("OAuth callback error:", error);
    res.status(500).send("Authentication failed: " + error.message);
  }
});

// Protected profile route with improved error handling
app.get("/profile", async (req, res) => {
  if (!req.session || !req.session.accessToken) {
    return res.redirect("/login");
  }
  
  try {
    // Validate token with OAuth server
    const validateResponse = await fetch(OAUTH_CONFIG.validateUrl, {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${req.session.accessToken}`
      }
    });
    
    if (!validateResponse.ok) {
      console.log("Token validation failed, redirecting to login");
      // Token is invalid, clear session and redirect to login
      if (req.session) {
        delete req.session.accessToken;
        delete req.session.refreshToken;
        delete req.session.user;
      }
      return res.redirect("/login");
    }
    
    const userData = await validateResponse.json();
    
    res.send(`
      <h1>User Profile</h1>
      <p><strong>Validated User Data from OAuth Server:</strong></p>
      <pre>${JSON.stringify(userData, null, 2)}</pre>
      <p><a href="/">Back to Home</a></p>
    `);
  } catch (error) {
    console.error("Profile validation error:", error);
    res.status(500).send("Failed to validate user: " + error.message);
  }
});

// Improved logout with better session handling
app.get("/logout", (req, res) => {
  if (!req.session) {
    return res.redirect("/");
  }
  
  // Clear session
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err);
      return res.status(500).send("Failed to logout");
    }
    console.log("User logged out successfully");
    res.redirect("/");
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).send("Internal server error");
});

// 404 handler
app.use((req, res) => {
  res.status(404).send("Page not found");
});

// Start server with validation
app.listen(PORT, () => {
  validateOAuthConfig();
  
  console.log(`
🚀 OAuth Client Example App running on http://localhost:${PORT}

Configuration:
- Auth Server: ${OAUTH_CONFIG.authUrl}
- Client ID: ${OAUTH_CONFIG.clientId}
- Redirect URI: ${OAUTH_CONFIG.redirectUri}

Make sure to:
1. Register this client with your OAuth server
2. Update OAUTH_CONFIG with your actual client credentials
3. Install required dependencies: npm install express express-session node-fetch crypto

Environment variables you can set:
- SESSION_SECRET
- OAUTH_CLIENT_ID  
- OAUTH_CLIENT_SECRET
- OAUTH_AUTH_URL
- OAUTH_TOKEN_URL
- OAUTH_VALIDATE_URL
- OAUTH_REDIRECT_URI
  `);
});