const User = require('../models/User');
const Token = require('../models/Token');
const emailService = require('../services/emailService');
const jwt = require('jsonwebtoken');
const { pool } = require('../config/database');

class AuthController {
  async register(req, res) {
    try {
      const { email, password, firstName, lastName } = req.body;

      // Check if user already exists
      const existingUser = await User.findByEmail(email);
      if (existingUser) {
        return res.status(400).json({ message: 'User already exists with this email' });
      }

      // Create user
      const userId = await User.create({ email, password, firstName, lastName });

      // Generate verification token
      const verificationToken = await Token.createEmailVerificationToken(userId);

      // Send verification email
      await emailService.sendVerificationEmail(email, verificationToken, firstName);

      res.status(201).json({
        message: 'User registered successfully. Please check your email for verification.',
        userId
      });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }

  async login(req, res) {
    try {
      const { email, password } = req.body;
      const ipAddress = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent');

      // Find user
      const user = await User.findByEmail(email);
      
      // Log login attempt
      await pool.execute(
        'INSERT INTO login_attempts (email, ip_address, user_agent, success) VALUES (?, ?, ?, ?)',
        [email, ipAddress, userAgent, false]
      );

      if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Check if account is locked
      if (user.locked_until && new Date() < new Date(user.locked_until)) {
        return res.status(423).json({ 
          message: 'Account is temporarily locked due to multiple failed login attempts',
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
        
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Check if user is active
      if (!user.is_active) {
        return res.status(401).json({ message: 'Account is deactivated' });
      }

      // Successful login
      await User.resetFailedAttempts(user.id);
      await User.updateLastLogin(user.id);
      
      // Update login attempt record
      await pool.execute(
        'UPDATE login_attempts SET success = TRUE WHERE email = ? AND ip_address = ? ORDER BY attempted_at DESC LIMIT 1',
        [email, ipAddress]
      );

      // Generate tokens
      const accessToken = jwt.sign(
        { userId: user.id, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
      );

      const refreshToken = await Token.createRefreshToken(user.id);

      // Interesting Send login alert email (optional)
      if (process.env.NODE_ENV === 'production') {
        await emailService.sendLoginAlert(user.email, user.first_name, ipAddress, userAgent);
      }

      res.json({
        message: 'Login successful',
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
      console.error('Login error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }

  async refreshToken(req, res) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return res.status(401).json({ message: 'Refresh token required' });
      }

      const tokenData = await Token.verifyRefreshToken(refreshToken);
      if (!tokenData) {
        return res.status(403).json({ message: 'Invalid or expired refresh token' });
      }

      const user = await User.findById(tokenData.user_id);
      if (!user || !user.is_active) {
        return res.status(403).json({ message: 'User not found or inactive' });
      }

      // Generate new access token
      const accessToken = jwt.sign(
        { userId: user.id, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
      );

      res.json({ accessToken });
    } catch (error) {
      console.error('Token refresh error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }

  async logout(req, res) {
    try {
      const { refreshToken } = req.body;

      if (refreshToken) {
        await Token.revokeRefreshToken(refreshToken);
      }

      res.json({ message: 'Logged out successfully' });
    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }

  async logoutAll(req, res) {
    try {
      const userId = req.user.id;
      await Token.revokeAllUserTokens(userId);
      res.json({ message: 'Logged out from all devices successfully' });
    } catch (error) {
      console.error('Logout all error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }

  async logoutAllUsers(req, res) {
    try {
      const { userId } = req.body;
      // if( !req.user.role === 'admin' ) {
      //   return res.status(403).json({ message: 'Forbidden: Admin access required' });
      // }
      await Token.emergencyrevoketokens();
      res.json({ message: 'Logged out from all devices successfully' });
    } catch (error) {
      console.error('Logout all error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }

  async verifyEmail(req, res) {
    try {
      const { token } = req.query;

      if (!token) {
        return res.status(400).json({ message: 'Verification token required' });
      }

      const tokenData = await Token.verifyEmailToken(token);
      if (!tokenData) {
        return res.status(400).json({ message: 'Invalid or expired verification token' });
      }

      await User.verifyEmail(tokenData.user_id);

      res.json({ message: 'Email verified successfully' });
    } catch (error) {
      console.error('Email verification error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }

  async resendVerificationEmail(req, res) {
    try {
      const { email } = req.body;

      const user = await User.findByEmail(email);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      if (user.is_verified) {
        return res.status(400).json({ message: 'Email is already verified' });
      }

      const verificationToken = await Token.createEmailVerificationToken(user.id);
      await emailService.sendVerificationEmail(user.email, verificationToken, user.first_name);

      res.json({ message: 'Verification email sent successfully' });
    } catch (error) {
      console.error('Resend verification error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }

  async forgotPassword(req, res) {
    try {
      const { email } = req.body;

      const user = await User.findByEmail(email);
      if (!user) {
        return res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
      }

      const resetToken = await Token.createPasswordResetToken(user.id);
      await emailService.sendPasswordResetEmail(user.email, resetToken, user.first_name);

      res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
    } catch (error) {
      console.error('Forgot password error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }

  async resetPassword(req, res) {
    try {
      const { token, newPassword } = req.body;
      
      const tokenData = await Token.verifyPasswordResetToken==(token);
      if (!tokenData) {
        return res.status(400).json({ message: 'Invalid or expired reset token' });
      }

      await User.updatePassword(tokenData.user_id, newPassword);
      
      // Revoke all refresh tokens to force re-login
      await Token.revokeAllUserTokens(tokenData.user_id);

      res.json({ message: 'Password reset successfully' });
    } catch (error) {
      console.error('Reset password error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }

  async changePassword(req, res) {
    try {
      const { currentPassword, newPassword } = req.body;
      const userId = req.user.id;

      const user = await User.findById(userId);
      const isValidPassword = await User.comparePassword(currentPassword, user.password);
      
      if (!isValidPassword) {
        return res.status(400).json({ message: 'Current password is incorrect' });
      }

      await User.updatePassword(userId, newPassword);
      
      // Revoke all refresh tokens to force re-login on other devices
      await Token.revokeAllUserTokens(userId);

      res.json({ message: 'Password changed successfully' });
    } catch (error) {
      console.error('Change password error:', error);
      res.status(500).json({ message: 'Internal server error' });
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
      console.error('Get profile error:', error);
      res.status(500).json({ message: 'Internal server error' });
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

      res.json({ message: 'Profile updated successfully' });
    } catch (error) {
      console.error('Update profile error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }

  async deactivateAccount(req, res) {
    try {
      const userId = req.user.id;
      
      await User.updateProfile(userId, { is_active: false });
      await Token.revokeAllUserTokens(userId);

      res.json({ message: 'Account deactivated successfully' });
    } catch (error) {
      console.error('Deactivate account error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }
}

module.exports = new AuthController();
