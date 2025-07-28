const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const router = express.Router();

// Admin schema
const adminUserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'admin' },
    failedLoginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date },
    lastLogin: { type: Date },
    passwordChangedAt: { type: Date },
    mustReauthenticate: { type: Boolean, default: false },
    previousPasswords: [{ type: String }]
});

adminUserSchema.methods.isLocked = function () {
    return this.lockUntil && this.lockUntil > Date.now();
};

adminUserSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    const hashed = await bcrypt.hash(this.password, 10);
    this.password = hashed;

    if (!this.isNew && this.previousPasswords) {
        if (this.previousPasswords.length >= 3) this.previousPasswords.shift();
        this.previousPasswords.push(hashed);
    }

    this.passwordChangedAt = new Date();
    next();
});

const AdminUser = mongoose.model('AdminUser', adminUserSchema);

// Middleware
const authAdmin = async (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ message: 'Access denied' });

    try {
        const decoded = jwt.verify(token, 'secret');
        const admin = await AdminUser.findById(decoded.id);
        if (!admin) return res.status(401).json({ message: 'Admin not found' });

        req.admin = admin;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

// Controller logic
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME_MS = 10 * 60 * 1000; // 10 minutes

router.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const existingUser = await AdminUser.findOne({ $or: [{ username }, { email }] });
        if (existingUser) return res.status(400).json({ message: 'Username or email already exists' });

        const admin = new AdminUser({ username, email, password });
        await admin.save();
        res.status(201).json({ message: 'Admin registered successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err });
    }
});

router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const admin = await AdminUser.findOne({ username });
        if (!admin) return res.status(400).json({ message: 'Invalid credentials' });

        if (admin.isLocked()) {
            return res.status(403).json({ message: 'Account temporarily locked. Try again later.' });
        }

        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
            admin.failedLoginAttempts += 1;
            if (admin.failedLoginAttempts >= MAX_LOGIN_ATTEMPTS) {
                admin.lockUntil = new Date(Date.now() + LOCK_TIME_MS);
            }
            await admin.save();
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        admin.failedLoginAttempts = 0;
        admin.lockUntil = null;
        const previousLogin = admin.lastLogin;
        admin.lastLogin = new Date();
        admin.mustReauthenticate = false;
        await admin.save();

        const token = jwt.sign({ id: admin._id }, 'secret', { expiresIn: '1h' });
        res.status(200).json({ message: 'Login successful', token, lastLogin: previousLogin });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err });
    }
});

router.post('/change-password', authAdmin, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        const admin = await AdminUser.findById(req.admin._id);

        const isMatch = await bcrypt.compare(oldPassword, admin.password);
        if (!isMatch) return res.status(400).json({ message: 'Incorrect current password' });

        const reused = await Promise.all(
            admin.previousPasswords.map(pw => bcrypt.compare(newPassword, pw))
        );
        if (reused.includes(true)) return res.status(400).json({ message: 'Cannot reuse previous passwords' });

        const now = new Date();
        if (admin.passwordChangedAt && now - admin.passwordChangedAt < 24 * 60 * 60 * 1000) {
            return res.status(400).json({ message: 'Password was recently changed. Try again later.' });
        }

        admin.password = newPassword;
        await admin.save();
        res.status(200).json({ message: 'Password changed successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err });
    }
});

module.exports = router;
