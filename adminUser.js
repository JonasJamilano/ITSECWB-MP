const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Audit = require('./Audit');
const router = express.Router();

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

    // Hash password before saving
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

const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME_MS = 10 * 60 * 1000;

// Middleware to protect routes by verifying JWT token
const authAdmin = async (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ message: 'Access denied, token missing' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
        const admin = await AdminUser.findById(decoded.id);
        if (!admin) return res.status(401).json({ message: 'Admin not found' });

        req.admin = admin;
        next();
    } catch (err) {
        return res.status(401).json({ message: 'Invalid token' });
    }
};

// Register route (no change)
router.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        const complexityRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;
        if (!complexityRegex.test(password)) {
            return res.status(400).json({
                message: "Password must be at least 8 characters with uppercase, lowercase, number, and special char"
            });
        }

        const existingUser = await AdminUser.findOne({ $or: [{ username }, { email }] });
        if (existingUser) return res.status(400).json({ message: 'Username or email already exists' });

        const admin = new AdminUser({ username, email, password });
        await admin.save();

        await Audit.create({
            userId: admin._id,
            username: admin.username,
            action: 'Admin Registered',
            details: `Admin ${admin.username} registered`
        });

        res.status(201).json({ message: 'Admin registered successfully' });
    } catch (err) {
        console.error('Error in admin register:', err);
        res.status(500).json({ message: 'Server error', error: err });
    }
});

// Login route (no change)
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

        const admin = await AdminUser.findOne({ email });
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

        const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET || 'secret', { expiresIn: '1h' });

        await Audit.create({
            userId: admin._id,
            username: admin.username,
            action: 'Admin Logged In',
            details: `Admin ${admin.username} logged in`
        });

        res.status(200).json({ message: 'Login successful', token, lastLogin: previousLogin });
    } catch (err) {
        console.error('Error in admin login:', err);
        res.status(500).json({ message: 'Server error', error: err });
    }
});

// Change password route - FIXED to hash new password and update previousPasswords properly
router.post('/change-password', authAdmin, async (req, res) => {
    try {
        const admin = req.admin;
        const { oldPassword, newPassword } = req.body;

        if (!oldPassword || !newPassword) {
            return res.status(400).json({ message: 'Old password and new password are required' });
        }

        const isMatch = await bcrypt.compare(oldPassword, admin.password);
        if (!isMatch) return res.status(400).json({ message: 'Incorrect current password' });

        // Check reuse of previous passwords including current
        const reused = await Promise.all(
            admin.previousPasswords.map(pw => bcrypt.compare(newPassword, pw))
        );
        const isSameAsCurrent = await bcrypt.compare(newPassword, admin.password);

        if (reused.includes(true) || isSameAsCurrent) {
            return res.status(400).json({ message: 'Cannot reuse previous passwords' });
        }

        const now = new Date();
        if (admin.passwordChangedAt && (now - admin.passwordChangedAt) < 24 * 60 * 60 * 1000) {
            return res.status(400).json({ message: 'Password was recently changed. Try again later.' });
        }

        // Set new password (will trigger pre save to hash and update previousPasswords)
        admin.password = newPassword;
        await admin.save();

        res.status(200).json({ message: 'Password changed successfully' });
    } catch (err) {
        console.error('Error changing admin password:', err);
        res.status(500).json({ message: 'Server error', error: err });
    }
});

// -------------- New routes below ---------------------

// Get all admins (manage accounts)
router.get('/manage-accounts', authAdmin, async (req, res) => {
    try {
        // Exclude sensitive fields from output
        const admins = await AdminUser.find({}, '-password -previousPasswords -failedLoginAttempts -lockUntil');
        res.json(admins);
    } catch (err) {
        console.error('Error fetching admins:', err);
        res.status(500).json({ message: 'Server error fetching accounts' });
    }
});

// Assign or update role for an admin
router.put('/assign-role/:id', authAdmin, async (req, res) => {
    try {
        const { role } = req.body;
        const validRoles = ['admin', 'superadmin', 'moderator', 'manager']; // Add 'manager' here

        if (!validRoles.includes(role)) {
            return res.status(400).json({ message: 'Invalid role specified' });
        }

        const adminToUpdate = await AdminUser.findById(req.params.id);
        if (!adminToUpdate) return res.status(404).json({ message: 'Admin user not found' });

        adminToUpdate.role = role;
        await adminToUpdate.save();

        await Audit.create({
            userId: req.admin._id,
            username: req.admin.username,
            action: 'Role Updated',
            details: `Changed role of ${adminToUpdate.username} to ${role}`
        });

        res.json({ message: 'Role updated successfully' });
    } catch (err) {
        console.error('Error updating role:', err);
        res.status(500).json({ message: 'Server error updating role' });
    }
});


// Delete admin account
router.delete('/manage-accounts/:id', authAdmin, async (req, res) => {
    try {
        const adminToDelete = await AdminUser.findById(req.params.id);
        if (!adminToDelete) return res.status(404).json({ message: 'Admin user not found' });

        await adminToDelete.deleteOne();

        await Audit.create({
            userId: req.admin._id,
            username: req.admin.username,
            action: 'Admin Deleted',
            details: `Deleted admin ${adminToDelete.username}`
        });

        res.json({ message: 'Admin deleted successfully' });
    } catch (err) {
        console.error('Error deleting admin:', err);
        res.status(500).json({ message: 'Server error deleting admin' });
    }
});

// View audit trail (all actions)
router.get('/audit-trail', authAdmin, async (req, res) => {
    try {
        // Sorted by timestamp descending, limit 100
        const audits = await Audit.find().sort({ timestamp: -1 }).limit(100);
        res.json(audits);
    } catch (err) {
        console.error('Error fetching audit trail:', err);
        res.status(500).json({ message: 'Server error fetching audit trail' });
    }
});

module.exports = router;
