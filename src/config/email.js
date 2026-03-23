const nodemailer = require('nodemailer');

// Email transporter configuration
const emailTransporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.EMAIL_PORT) || 587,
  secure: false, // true for 465, false for 587
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  logger: process.env.NODE_ENV !== 'production',
  debug: process.env.NODE_ENV !== 'production'
});

module.exports = emailTransporter;
