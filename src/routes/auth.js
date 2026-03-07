const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { isAuthenticated, isAdmin } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');
const { body } = require('express-validator');

// Login validation
const loginValidation = [
  body('username').trim().notEmpty().withMessage('Username is required'),
  body('password').notEmpty().withMessage('Password is required')
];

// Routes
router.post('/login', authLimiter, loginValidation, authController.login);
router.post('/logout', authController.logout);
router.get('/check-auth', authController.checkAuth);
router.get('/auth-status', authController.getAuthStatus);
router.get('/me', authController.getMe);
router.get('/users', isAuthenticated, isAdmin, authController.getAllUsers);
router.put('/user/profile', isAuthenticated, authController.updateProfile);

module.exports = router;
