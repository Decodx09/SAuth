// test-email.js
const nodemailer = require("nodemailer");
require("dotenv").config();

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false, 
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

const mailOptions = {
  from: `"Shivansh" <${process.env.EMAIL_USER}>`,
  to: "shivanshsukhijaengineer@gmail.com",
  subject: "SMTP Test",
  text: "If you received this, SMTP is working!",
};

transporter.sendMail(mailOptions, (error, info) => {
  if (error) {
    return console.error("Error sending email:", error);
  }
  console.log("Email sent:", info.response);
});
