const nodemailer = require("nodemailer");

class EmailService {
  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      }
    });
  }

  async sendVerificationEmail(email, token, firstName) {
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Verify Your Email Address",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Welcome ${firstName}!</h2>
          <p>Thank you for registering. Please verify your email address by clicking the link below:</p>
          <a href="${verificationUrl}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
            Verify Email
          </a>
          <p>If the button doesn't work, copy and paste this link into your browser:</p>
          <p>${verificationUrl}</p>
          <p>This link will expire in 24 hours.</p>
          <p>If you didn't create this account, please ignore this email.</p>
        </div>
      `
    };

    await this.transporter.sendMail(mailOptions);
  }

  async sendPasswordResetEmail(email, token, firstName) {
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset Request",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Hello ${firstName},</h2>
          <p>You requested a password reset. Click the link below to reset your password:</p>
          <a href="${resetUrl}" style="background-color: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
            Reset Password
          </a>
          <p>If the button doesn't work, copy and paste this link into your browser:</p>
          <p>${resetUrl}</p>
          <p>This link will expire in 1 hour.</p>
          <p>If you didn't request this reset, please ignore this email and your password will remain unchanged.</p>
        </div>
      `
    };

    await this.transporter.sendMail(mailOptions);
  }

  async sendLoginAlert(email, firstName, ipAddress, userAgent) {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "New Login to Your Account",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Hello ${firstName},</h2>
          <p>We detected a new login to your account:</p>
          <ul>
            <li><strong>Time:</strong> ${new Date().toLocaleString()}</li>
            <li><strong>IP Address:</strong> ${ipAddress}</li>
            <li><strong>Device:</strong> ${userAgent}</li>
          </ul>
          <p>If this was you, you can ignore this email. If you don't recognize this activity, please secure your account immediately by changing your password.</p>
        </div>
      `
    };

    await this.transporter.sendMail(mailOptions);
  }
}

module.exports = new EmailService();
