const { pool } = require("../config/database");
const crypto = require("crypto");

class Token {
  static async createEmailVerificationToken(userId) {
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    
    await pool.execute(
      "INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
      [userId, token, expiresAt]
    );
    
    return token;
  }

  static async createPasswordResetToken(userId) {
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    
    await pool.execute(
      "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
      [userId, token, expiresAt]
    );
    return token;
  }

  static async verifyEmailToken(token) {
    const [rows] = await pool.execute(
      "SELECT * FROM email_verification_tokens WHERE token = ? AND expires_at > NOW()",
      [token]
    );
    if (rows.length === 0) return null;
    
    // Delete used token
    await pool.execute(
      "DELETE FROM email_verification_tokens WHERE token = ?",
      [token]
    );
    
    return rows[0];
  }

  static async verifyPasswordResetToken(token) {
    const [rows] = await pool.execute(
      "SELECT * FROM password_reset_tokens WHERE token = ? AND expires_at > NOW() AND used = FALSE",
      [token]
    );
    
    if (rows.length === 0) return null;
    
    // Mark token as used
    await pool.execute(
      "UPDATE password_reset_tokens SET used = TRUE WHERE token = ?",
      [token]
    );
    
    return rows[0];
  }

  static async createRefreshToken(userId) {
    const token = crypto.randomBytes(64).toString("hex");
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    
    await pool.execute(
      "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
      [userId, token, expiresAt]
    );
    
    return token;
  }

  static async verifyRefreshToken(token) {
    const [rows] = await pool.execute(
      "SELECT * FROM refresh_tokens WHERE token = ? AND expires_at > NOW()",
      [token]
    );
    
    return rows[0];
  }

  static async revokeRefreshToken(token) {
    await pool.execute(
      "DELETE FROM refresh_tokens WHERE token = ?",
      [token]
    );
  }

  static async emergencyrevoketokens() {
    await pool.execute("DELETE FROM refresh_tokens");
  }

  static async revokeAllUserTokens(userId) {
    await pool.execute(
      "DELETE FROM refresh_tokens WHERE user_id = ?",
      [userId]
    );
  }
}

module.exports = Token;