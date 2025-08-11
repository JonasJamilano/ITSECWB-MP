const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('./adminUser');
const Audit = require('./Audit');

// Middleware to authenticate and check admin role
const authAdmin = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('🔍 Decoded token payload:', decoded);

    const admin = await User.findById(decoded.id);
    console.log('🗄️ Admin from DB:', admin);

    if (!admin) {
      return res.status(401).json({ message: 'User not found' });
    }

    if (admin.role?.toLowerCase() !== 'admin') {
      console.log('❌ Unauthorized - Role is:', admin.role);
      return res.status(403).json({ message: 'Not authorized' });
    }

    req.user = admin;
    next();
  } catch (err) {
    console.error('Error in authAdmin:', err);
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// Assign role route
router.put('/assign-role/:id', authAdmin, async (req, res) => {
  try {
    const { role } = req.body;

    // Allowed roles
    const allowedRoles = ['Admin', 'Manager', 'User'];
    if (!allowedRoles.map(r => r.toLowerCase()).includes(role.toLowerCase())) {
      return res.status(400).json({ message: 'Invalid role' });
    }

    // Update role
    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      { role },
      { new: true, runValidators: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Save audit log
    await Audit.create({
      userId: req.params.id,
      username: updatedUser.username,
      action: 'Role Change',
      details: `Role changed to ${role}`,
    });

    res.json({ message: 'Role updated successfully', updatedUser });
  } catch (err) {
    console.error('Error updating role:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

module.exports = router;
