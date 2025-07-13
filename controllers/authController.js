const User = require("../models/User");
const Token = require("../models/Token");
const emailService = require("../services/emailService");
const jwt = require("jsonwebtoken");
const { pool } = require("../config/database");
const crypto = require("crypto");

const generateAccessToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: "1h" });
};

class AuthController {

  async generateAuthCode(req, res){
    try {
      const { client_id, redirect_uri, state, response_type } = req.query;
      
      // Validate client application
      const [client] = await pool.execute(
        "SELECT * FROM oauth_clients WHERE client_id = ? AND redirect_uri = ?",
        [client_id, redirect_uri]
      );
      
      if (!client.length) {
        return res.status(400).json({ error: "Invalid client" });
      }
      
      // Check if user is logged in
      if (!req.user) {
        // Store the OAuth request and redirect to login
        req.session.oauthRequest = { client_id, redirect_uri, state };
        return res.redirect("/login?oauth=true");
      }
      
      // Generate authorization code
      const code = crypto.randomBytes(32).toString("hex");
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
      
      // Store authorization code
      await pool.execute(
        "INSERT INTO authorization_codes (code, user_id, client_id, redirect_uri, expires_at) VALUES (?, ?, ?, ?, ?)",
        [code, req.user.id, client_id, redirect_uri, expiresAt]
      );
      
      // Redirect back to client with code
      const redirectUrl = new URL(redirect_uri);
      redirectUrl.searchParams.append("code", code);
      if (state) redirectUrl.searchParams.append("state", state);
      
      res.redirect(redirectUrl.toString());
    } catch (error) {
      console.error("Authorization error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  };

  async validateToken(req, res) {
    try {
      const authHeader = req.headers.authorization;
      const token = authHeader && authHeader.split(" ")[1];
      
      if (!token) {
        return res.status(401).json({ error: "No token provided" });
      }
      
      // Verify JWT
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Get fresh user data
      const [users] = await pool.execute(
        "SELECT id, email, first_name, last_name, role, is_active FROM users WHERE id = ?",
        [decoded.userId]
      );
      
      if (!users.length || !users[0].is_active) {
        return res.status(401).json({ error: "User not found or inactive" });
      }
      
      res.json({
        valid: true,
        user: {
          id: users[0].id,
          email: users[0].email,
          name: `${users[0].first_name} ${users[0].last_name}`,
          role: users[0].role
        }
      });
    } catch (error) {
      if (error.name === "JsonWebTokenError") {
        return res.status(401).json({ error: "Invalid token" });
      }
      console.error("Token validation error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  };

async authorize(req, res) {
  try {
    const { client_id, redirect_uri, response_type, state, scope } = req.query;
    
    // Validate required parameters
    if (!client_id || !redirect_uri || response_type !== "code") {
      return res.status(400).json({ error: "Invalid request parameters" });
    }
    
    // Validate OAuth client
    const [client] = await pool.execute(
      "SELECT * FROM oauth_clients WHERE client_id = ?",
      [client_id]
    );
    
    if (!client.length) {
      return res.status(400).json({ error: "Invalid client_id" });
    }
    
    // Validate redirect_uri
    const validRedirectUris = client[0].redirect_uri.split(",");
    if (!validRedirectUris.some(uri => uri.trim() === redirect_uri)) {
      return res.status(400).json({ error: "Invalid redirect_uri" });
    }
    
    // Check if user is already authenticated
    const authToken = req.cookies.accessToken || req.headers.authorization?.split(" ")[1];
    
    if (authToken) {
      try {
        const decoded = jwt.verify(authToken, process.env.JWT_SECRET);
        const [user] = await pool.execute(
          "SELECT id FROM users WHERE id = ? AND is_active = 1",
          [decoded.userId]
        );
        
        if (user.length) {
          // User is authenticated, generate code immediately
          const crypto = require("crypto");
          const code = crypto.randomBytes(32).toString("hex");
          const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
          
          await pool.execute(
            "INSERT INTO authorization_codes (code, user_id, client_id, redirect_uri, scope, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
            [code, decoded.userId, client_id, redirect_uri, scope || " ", expiresAt]
          );
          
          const redirectUrl = new URL(redirect_uri);
          redirectUrl.searchParams.append("code", code);
          if (state) redirectUrl.searchParams.append("state", state);
          
          return res.redirect(redirectUrl.toString());
        }
      } catch (error) {
        // Token invalid, proceed to login
      }
    }
    
    // Store OAuth request in session and redirect to login
    req.session.oauthRequest = { client_id, redirect_uri, state, scope };
    
    // Redirect to login page with OAuth indicator
    res.redirect(`/login?oauth=true&client=${encodeURIComponent(client[0].name)}`);
  } catch (error) {
    console.error("Authorization error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
}

// Token Exchange Endpoint
async token(req, res) {
  try {
    const { grant_type, code, client_id, client_secret, redirect_uri, refresh_token } = req.body;
    
    // Handle authorization code grant
    if (grant_type === "authorization_code") {
      // Validate client credentials
      const [client] = await pool.execute(
        "SELECT * FROM oauth_clients WHERE client_id = ? AND client_secret = ?",
        [client_id, client_secret]
      );
      
      if (!client.length) {
        return res.status(401).json({ error: "invalid_client" });
      }
      
      // Validate authorization code
      const [authCode] = await pool.execute(
        "SELECT * FROM authorization_codes WHERE code = ? AND client_id = ? AND redirect_uri = ? AND expires_at > NOW() AND used = 0",
        [code, client_id, redirect_uri]
      );
      
      if (!authCode.length) {
        return res.status(400).json({ error: "invalid_grant" });
      }
      
      // Mark code as used
      await pool.execute(
        "UPDATE authorization_codes SET used = 1 WHERE code = ?",
        [code]
      );
      
      // Get user data
      const [user] = await pool.execute(
        "SELECT id, email, first_name, last_name, role, is_verified FROM users WHERE id = ?",
        [authCode[0].user_id]
      );
      
      if (!user.length) {
        return res.status(400).json({ error: "invalid_grant" });
      }
      
      // Generate tokens
      const accessToken = jwt.sign(
        { 
          userId: user[0].id, 
          email: user[0].email, 
          role: user[0].role,
          client_id: client_id 
        },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );
      
      const refreshToken = await Token.createRefreshToken(user[0].id, client_id);
      
      // Set cookies if requested
      if (req.body.setCookies) {
        res.cookie("accessToken", accessToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
          domain: req.body.cookieDomain || undefined,
          maxAge: 60 * 60 * 1000 // 1 hour
        });
        
        res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
          domain: req.body.cookieDomain || undefined,
          maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
        });
      }
      
      return res.json({
        access_token: accessToken,
        refresh_token: refreshToken,
        token_type: "Bearer",
        expires_in: 3600,
        scope: authCode[0].scope || " ",
        user: {
          id: user[0].id,
          email: user[0].email,
          firstName: user[0].first_name,
          lastName: user[0].last_name,
          role: user[0].role,
          isVerified: user[0].is_verified
        }
      });
    }
    
    // Handle refresh token grant
    if (grant_type === "refresh_token") {
      // Implementation for refresh token...
      // Similar to your existing refreshToken method
    }
    
    return res.status(400).json({ error: "unsupported_grant_type" });
  } catch (error) {
    console.error("Token exchange error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
}

// Introspection endpoint (to validate tokens)
async introspect(req, res) {
  try {
    const { token, token_type_hint } = req.body;
    const authHeader = req.headers.authorization;
    
    // Validate client credentials (Basic auth)
    if (!authHeader || !authHeader.startsWith("Basic ")) {
      return res.status(401).json({ error: "Invalid client authentication" });
    }
    
    const credentials = Buffer.from(authHeader.slice(6), "base64").toString();
    const [client_id, client_secret] = credentials.split(":");
    
    const [client] = await pool.execute(
      "SELECT * FROM oauth_clients WHERE client_id = ? AND client_secret = ?",
      [client_id, client_secret]
    );
    
    if (!client.length) {
      return res.status(401).json({ error: "Invalid client credentials" });
    }
    
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Verify token belongs to this client
      if (decoded.client_id && decoded.client_id !== client_id) {
        return res.json({ active: false });
      }
      
      const [user] = await pool.execute(
        "SELECT id, email, role, is_active FROM users WHERE id = ?",
        [decoded.userId]
      );
      
      if (!user.length || !user[0].is_active) {
        return res.json({ active: false });
      }
      
      res.json({
        active: true,
        scope: decoded.scope || " ",
        client_id: decoded.client_id || client_id,
        username: user[0].email,
        exp: decoded.exp,
        iat: decoded.iat,
        sub: decoded.userId.toString(),
        aud: client_id,
        role: user[0].role
      });
    } catch (error) {
      res.json({ active: false });
    }
  } catch (error) {
    console.error("Introspection error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
}

  async register(req, res) {
    try {
      const { email, password, firstName, lastName } = req.body;

      // Check if user already exists
      const existingUser = await User.findByEmail(email);
      if (existingUser) {
        return res.status(400).json({ message: "User already exists with this email" });
      }

      // Create user
      const userId = await User.create({ email, password, firstName, lastName });

      // Generate verification token
      const verificationToken = await Token.createEmailVerificationToken(userId);

      // Send verification email
      await emailService.sendVerificationEmail(email, verificationToken, firstName);

      res.status(201).json({
        message: "User registered successfully. Please check your email for verification.",
        userId
      });
    } catch (error) {
      console.error("Registration error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }

  async login(req, res) {
    try {
      const { email, password } = req.body;
      const ipAddress = req.ip || req.connection.remoteAddress;
      const userAgent = req.get("User-Agent");
  
      // Find user
      const user = await User.findByEmail(email);
      
      // Log login attempt
      await pool.execute(
        "INSERT INTO login_attempts (email, ip_address, user_agent, success) VALUES (?, ?, ?, ?)",
        [email, ipAddress, userAgent, false]
      );
  
      if (!user) {
        return res.status(401).json({ message: "Invalid credentials" });
      }
  
      // Check if account is locked
      if (user.locked_until && new Date() < new Date(user.locked_until)) {
        return res.status(423).json({ 
          message: "Account is temporarily locked due to multiple failed login attempts",
          lockedUntil: user.locked_until
        });
      }
  
      // Verify password
      const isValidPassword = await User.comparePassword(password, user.password);
      if (!isValidPassword) {
        await User.incrementFailedAttempts(user.id);
        
        // Lock account after 5 failed attempts
        if (user.failed_login_attempts >= 10) {
          const lockUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
          await User.lockAccount(user.id, lockUntil);
        }
        
        return res.status(401).json({ message: "Invalid credentials" });
      }

      if (!user.is_active) {
        return res.status(401).json({ message: "Account is deactivated" });
      }
  
      // Successful login
      await User.resetFailedAttempts(user.id);
      await User.updateLastLogin(user.id);
      
      // Update login attempt record
      await pool.execute(
        "UPDATE login_attempts SET success = TRUE WHERE email = ? AND ip_address = ? ORDER BY attempted_at DESC LIMIT 1",
        [email, ipAddress]
      );
  
      // Check if this is an OAuth flow (from session or query params)
      const oauthRequest = req.session?.oauthRequest || req.body.oauthRequest;
      
      if (oauthRequest) {
        const { client_id, redirect_uri, state, scope } = oauthRequest;
        
        // Validate OAuth client
        const [client] = await pool.execute(
          "SELECT * FROM oauth_clients WHERE client_id = ? AND redirect_uri LIKE ?",
          [client_id, `%${redirect_uri}%`]
        );
        
        if (!client.length) {
          return res.status(400).json({ error: "Invalid OAuth client" });
        }
        
        // Generate authorization code
        const crypto = require("crypto");
        const code = crypto.randomBytes(32).toString("hex");
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
        
        // Store authorization code
        await pool.execute(
          "INSERT INTO authorization_codes (code, user_id, client_id, redirect_uri, scope, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
          [code, user.id, client_id, redirect_uri, scope || " ", expiresAt]
        );
        
        // Clear OAuth request from session
        if (req.session?.oauthRequest) {
          delete req.session.oauthRequest;
        }
        
        // Send login alert
        if (process.env.NODE_ENV === "production") {
          await emailService.sendLoginAlert(user.email, user.first_name, ipAddress, userAgent);
        }
        
        // Return redirect URL instead of tokens
        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.append("code", code);
        if (state) redirectUrl.searchParams.append("state", state);
        
        return res.json({ 
          message: "Login successful",
          oauth: true,
          redirectUrl: redirectUrl.toString()
        });
      }
  
      // Normal login flow - Generate tokens
      const accessToken = jwt.sign(
        { userId: user.id, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: "15m" }
      );
  
      const refreshToken = await Token.createRefreshToken(user.id);
  
      // Set cookies if requested
      if (req.body.setCookies || req.query.setCookies) {
        res.cookie("accessToken", accessToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
          maxAge: 15 * 60 * 1000 // 15 minutes
        });
  
        res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
          maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
        });
      }
  
      if (process.env.NODE_ENV === "production") {
        await emailService.sendLoginAlert(user.email, user.first_name, ipAddress, userAgent);
      }
  
      res.json({
        message: "Login successful",
        accessToken,
        refreshToken,
        user: {
          id: user.id,
          email: user.email,
          firstName: user.first_name,
          lastName: user.last_name,
          isVerified: user.is_verified,
          role: user.role
        }
      });
    } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }

  async refreshToken(req, res) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return res.status(401).json({ message: "Refresh token required" });
      }

      const tokenData = await Token.verifyRefreshToken(refreshToken);
      if (!tokenData) {
        return res.status(403).json({ message: "Invalid or expired refresh token" });
      }

      const user = await User.findById(tokenData.user_id);
      if (!user || !user.is_active) {
        return res.status(403).json({ message: "User not found or inactive" });
      }

      // Generate new access token
      const accessToken = jwt.sign(
        { userId: user.id, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: "15m" }
      );

      res.json({ accessToken });
    } catch (error) {
      console.error("Token refresh error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }

  async logout(req, res) {
    try {
      const { refreshToken } = req.body;

      if (refreshToken) {
        await Token.revokeRefreshToken(refreshToken);
      }

      res.json({ message: "Logged out successfully" });
    } catch (error) {
      console.error("Logout error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }

  async logoutAll(req, res) {
    try {
      const userId = req.user.id;
      await Token.revokeAllUserTokens(userId);
      res.json({ message: "Logged out from all devices successfully" });
    } catch (error) {
      console.error("Logout all error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }

  async logoutAllUsers(req, res) {
    try {
      const { userId } = req.body;
      if( !req.user.role === "admin" ) {
        return res.status(403).json({ message: "Forbidden: Admin access required" });
      }
      await Token.emergencyrevoketokens();
      res.json({ message: "Logged out from all devices successfully" });
    } catch (error) {
      console.error("Logout all error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }

  async verifyEmail(req, res) {
    try {
      const { token } = req.query;

      if (!token) {
        return res.status(400).json({ message: "Verification token required" });
      }

      const tokenData = await Token.verifyEmailToken(token);
      if (!tokenData) {
        return res.status(400).json({ message: "Invalid or expired verification token" });
      }

      await User.verifyEmail(tokenData.user_id);

      res.json({ message: "Email verified successfully" });
    } catch (error) {
      console.error("Email verification error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }

  async resendVerificationEmail(req, res) {
    try {
      const { email } = req.body;

      const user = await User.findByEmail(email);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      if (user.is_verified) {
        return res.status(400).json({ message: "Email is already verified" });
      }

      const verificationToken = await Token.createEmailVerificationToken(user.id);
      await emailService.sendVerificationEmail(user.email, verificationToken, user.first_name);

      res.json({ message: "Verification email sent successfully" });
    } catch (error) {
      console.error("Resend verification error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }

  async forgotPassword(req, res) {
    try {
      const { email } = req.body;

      const user = await User.findByEmail(email);
      if (!user) {
        return res.json({ message: "If an account with that email exists, a password reset link has been sent." });
      }

      const resetToken = await Token.createPasswordResetToken(user.id);
      await emailService.sendPasswordResetEmail(user.email, resetToken, user.first_name);

      res.json({ message: "If an account with that email exists, a password reset link has been sent." });
    } catch (error) {
      console.error("Forgot password error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }

  async resetPassword(req, res) {
    try {
      const { token, newPassword } = req.body;
      
      const tokenData = await Token.verifyPasswordResetToken==(token);
      if (!tokenData) {
        return res.status(400).json({ message: "Invalid or expired reset token" });
      }

      await User.updatePassword(tokenData.user_id, newPassword);
      
      // Revoke all refresh tokens to force re-login
      await Token.revokeAllUserTokens(tokenData.user_id);

      res.json({ message: "Password reset successfully" });
    } catch (error) {
      console.error("Reset password error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }

  async changePassword(req, res) {
    try {
      const { currentPassword, newPassword } = req.body;
      const userId = req.user.id;

      const user = await User.findById(userId);
      const isValidPassword = await User.comparePassword(currentPassword, user.password);
      
      if (!isValidPassword) {
        return res.status(400).json({ message: "Current password is incorrect" });
      }

      await User.updatePassword(userId, newPassword);
      
      // Revoke all refresh tokens to force re-login on other devices
      await Token.revokeAllUserTokens(userId);

      res.json({ message: "Password changed successfully" });
    } catch (error) {
      console.error("Change password error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }

  async getProfile(req, res) {
    try {
      const user = req.user;
      res.json({
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        isVerified: user.is_verified,
        role: user.role,
        createdAt: user.created_at,
        lastLogin: user.last_login
      });
    } catch (error) {
      console.error("Get profile error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }

  async updateProfile(req, res) {
    try {
      const { firstName, lastName } = req.body;
      const userId = req.user.id;

      const updates = {};
      if (firstName) updates.first_name = firstName;
      if (lastName) updates.last_name = lastName;

      await User.updateProfile(userId, updates);

      res.json({ message: "Profile updated successfully" });
    } catch (error) {
      console.error("Update profile error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }

  async activateAccount(req, res) {
    try {
      const userId = req.user.id;
      
      await User.updateProfile(userId, { is_active: true });

      res.json({ message: "Account activated successfully" });
    } catch (error) {
      console.error("Activate account error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }

  async deactivateAccount(req, res) {
    try {
      const userId = req.user.id;
      
      await User.updateProfile(userId, { is_active: false });
      await Token.revokeAllUserTokens(userId);

      res.json({ message: "Account deactivated successfully" });
    } catch (error) {
      console.error("Deactivate account error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
}

module.exports = new AuthController();
