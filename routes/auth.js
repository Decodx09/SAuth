const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authenticateToken, requireEmailVerification, requireRole } = require('../middleware/auth');
const { authLimiter, passwordResetLimiter } = require('../middleware/rateLimiter');
const { validateRegistration, validateLogin, validatePasswordReset } = require('../middleware/validation');
const { pool } = require('../config/database');

// Public routes
router.post('/register', authLimiter, validateRegistration, authController.register);
router.post('/login', authLimiter, validateLogin, authController.login);
router.post('/refresh-token', authController.refreshToken);
router.get('/verify-email', authController.verifyEmail);
router.post('/resend-verification', authLimiter, authController.resendVerificationEmail);
router.post('/forgot-password', passwordResetLimiter, authController.forgotPassword);
router.post('/reset-password', passwordResetLimiter, validatePasswordReset, authController.resetPassword);

// Protected routes
router.post('/logout', authenticateToken, authController.logout);
router.post('/logout-all', authenticateToken, authController.logoutAll);
router.get('/profile', authenticateToken, authController.getProfile);
router.put('/profile', authenticateToken, authController.updateProfile);
router.post('/change-password', authenticateToken, requireEmailVerification, authController.changePassword);
router.post('/deactivate', authenticateToken, requireEmailVerification, authController.deactivateAccount);
router.post('/logout-all-users', authenticateToken, requireRole(['admin']), authController.logoutAllUsers);

router.get('/admin/users', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const [users] = await pool.execute(
      'SELECT id, email, first_name, last_name, is_verified, is_active, role, created_at, last_login FROM users ORDER BY created_at DESC'
    );
    res.json({ users });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

module.exports = router;