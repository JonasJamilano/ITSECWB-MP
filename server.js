const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const bcrypt = require("bcrypt");
const Audit = require("./Audit");

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// Serve static files from current directory (HTML, CSS, JS, images, uploads all here)
app.use(express.static(__dirname));

// Multer setup for uploads - save files to current directory
const storage = multer.diskStorage({
    destination: __dirname,
    filename: (req, file, cb) => {
        cb(null, Date.now() + "-" + file.originalname);
    }
});
const upload = multer({ storage });

// MongoDB Connection
mongoose.connect("mongodb://localhost:27017/webcafe", {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log("✅ Connected to MongoDB"))
.catch(err => console.error("❌ MongoDB Connection Error:", err));

// User schema/model with all fields
const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String,
    passwordHistory: [String],
    passwordLastChanged: { type: Date, default: new Date(0) },
    firstName: String,
    lastName: String,
    description: String,
    avatar: String,
    loginAttempts: { type: Number, default: 0 },
    lockUntil: Date,
    lastLogin: Date,
    lastAttempt: Date,
    role: { type: String, default: "customer" }
});

userSchema.methods.isLocked = function () {
    return this.lockUntil && this.lockUntil > Date.now();
};

userSchema.methods.incrementLoginAttempts = async function () {
    if (this.lockUntil && this.lockUntil < Date.now()) {
        this.loginAttempts = 1;
        this.lockUntil = undefined;
    } else {
        this.loginAttempts += 1;
        if (this.loginAttempts >= 5) {
            this.lockUntil = new Date(Date.now() + 5 * 60 * 1000); // lock for 5 minutes
        }
    }
    return this.save();
};

userSchema.methods.resetLoginAttempts = async function () {
    this.loginAttempts = 0;
    this.lockUntil = undefined;
    return this.save();
};

const User = mongoose.model("User", userSchema);

// Review schema/model
const reviewSchema = new mongoose.Schema({
    userId: String,
    username: String,
    branch: String,
    rating: Number,
    text: String,
    date: { type: Date, default: Date.now }
});
const Review = mongoose.model("Review", reviewSchema);

// ======================== ROUTES ========================

// Homepage route (serve Homepage.html)
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "Homepage.html"));
});

// Password Reset Route
app.post('/reset-password', async (req, res) => {
    const { email, newPassword } = req.body;
  
    if (!email || !newPassword) {
      return res.status(400).json({ message: '❌ Email and new password are required.' });
    }
  
    try {
      const user = await User.findOne({ email });
  
      if (!user) {
        return res.status(404).json({ message: '❌ No user found with that email.' });
      }
  
      const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
      if (!passwordRegex.test(newPassword)) {
        return res.status(400).json({
          message: '❌ Password must include uppercase, lowercase, number, special character, and be at least 8 characters.'
        });
      }
  
      const usedBefore = await Promise.any([
        bcrypt.compare(newPassword, user.password),
        ...(user.passwordHistory || []).map(oldHash => bcrypt.compare(newPassword, oldHash))
      ]).catch(() => false);
  
      if (usedBefore) {
        return res.status(400).json({
          message: '⚠️ You’ve used this password before. Please choose a new one.'
        });
      }
  
      const hashedPassword = await bcrypt.hash(newPassword, 10);
  
      const history = user.passwordHistory || [];
      history.unshift(user.password);
      if (history.length > 5) history.pop();
  
      user.password = hashedPassword;
      user.passwordHistory = history;
      user.passwordLastChanged = new Date();
  
      await user.save();
  
      res.json({ message: '✅ Password successfully reset!' });
    } catch (error) {
      console.error('❌ Error resetting password:', error);
      res.status(500).json({ message: '❌ Server error while resetting password.' });
    }
  });

// Change password (logged-in user) - verify old password first
app.put("/change-password/:id", async (req, res) => {
  try {
    const userId = req.params.id;
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
      return res.status(400).json({ success: false, message: "Old and new passwords are required." });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    // Verify old password
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: "Old password is incorrect." });
    }

    // Validate new password complexity
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 8 characters and include uppercase, lowercase, a number and a special character."
      });
    }

    // Prevent reuse of current/recent passwords
    const usedBefore = await Promise.any([
      bcrypt.compare(newPassword, user.password),
      ...(user.passwordHistory || []).map(h => bcrypt.compare(newPassword, h))
    ]).catch(() => false);

    if (usedBefore) {
      return res.status(400).json({ success: false, message: "You have used this password before. Choose a new one." });
    }

    // Push current password into history, keep last 5
    const history = user.passwordHistory || [];
    history.unshift(user.password);
    if (history.length > 5) history.length = 5;

    // Hash & set new password
    const hashed = await bcrypt.hash(newPassword, 10);
    user.password = hashed;
    user.passwordHistory = history;
    user.passwordLastChanged = new Date();

    await user.save();

    return res.json({ success: true, message: "✅ Password changed successfully!" });
  } catch (err) {
    console.error("❌ Error in /change-password:", err);
    return res.status(500).json({ success: false, message: "Server error while changing password." });
  }
});

// ---------- FIXED: Update Profile (PUT /update-profile/:id) ----------
app.put("/update-profile/:id", async (req, res) => {
  try {
    const { email, username, firstName, lastName, description } = req.body;

    const updatedFields = {};
    if (email) updatedFields.email = email;
    if (username) updatedFields.username = username;
    if (typeof firstName !== "undefined") updatedFields.firstName = firstName;
    if (typeof lastName !== "undefined") updatedFields.lastName = lastName;
    if (typeof description !== "undefined") updatedFields.description = description;

    // findByIdAndUpdate returns the updated doc with { new: true }
    const updatedUser = await User.findByIdAndUpdate(req.params.id, updatedFields, { new: true });

    if (!updatedUser) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // don't send password fields back
    const userResponse = {
      _id: updatedUser._id,
      username: updatedUser.username,
      email: updatedUser.email,
      firstName: updatedUser.firstName,
      lastName: updatedUser.lastName,
      description: updatedUser.description,
      avatar: updatedUser.avatar
    };

    res.json({ success: true, message: "✅ Profile updated successfully!", user: userResponse });
  } catch (error) {
    console.error("❌ Error updating profile:", error);
    res.status(500).json({ success: false, message: "❌ Error updating profile." });
  }
});

// Update Avatar
app.put("/update-avatar/:id", upload.single("avatar"), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: "❌ No file uploaded." });
        }

        const updatedUser = await User.findByIdAndUpdate(
            req.params.id,
            { avatar: "/uploads/" + req.file.filename },
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ message: "❌ User not found." });
        }

        res.json({ message: "✅ Profile picture updated!", avatar: updatedUser.avatar });
    } catch (err) {
        console.error("❌ Error updating profile picture:", err);
        res.status(500).json({ message: "Error updating profile picture." });
    }
});

// Registration route (user)
app.post("/register", upload.single("avatar"), async (req, res) => {
    try {
        const { username, email, password, description } = req.body;
        const avatar = req.file ? req.file.filename : null;

        if (await User.findOne({ email })) {
            return res.status(400).json({ message: "❌ Email already registered." });
        }

        const complexityRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;
        if (!complexityRegex.test(password)) {
            return res.status(400).json({
                message: "❌ Password must be at least 8 characters and include uppercase, lowercase, number, and special character."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            username,
            email,
            password: hashedPassword,
            passwordLastChanged: new Date(),
            description,
            avatar,
            role: "customer"
        });

        await newUser.save();

        // Audit log
        try {
            await Audit.create({
                userId: newUser._id,
                username: newUser.username,
                action: "User Registered",
                details: `User ${newUser.username} registered with role customer`
            });
        } catch (auditErr) {
            console.error("Audit log creation failed:", auditErr);
        }

        res.json({ message: "✅ User registered successfully!" });
    } catch (err) {
        console.error("❌ Error in registration:", err);
        res.status(500).json({ message: "Error registering user." });
    }
});

// Admin register route (role selection)
app.post("/admin/register", multer().none(), async (req, res) => {
    try {
        const { username, email, password, role } = req.body;

        if (!username || !email || !password || !role) {
            return res.status(400).json({ message: "All fields are required." });
        }

        const validRoles = ["admin", "roleA"];
        if (!validRoles.includes(role)) {
            return res.status(400).json({ message: "Invalid role." });
        }

        if (await User.findOne({ email })) {
            return res.status(400).json({ message: "Email already registered." });
        }

        const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;
        if (!regex.test(password)) {
            return res.status(400).json({
                message: "Password must be at least 8 characters with uppercase, lowercase, number and special character."
            });
        }

        const hashed = await bcrypt.hash(password, 10);

        const newUser = new User({
            username,
            email,
            password: hashed,
            role,
            passwordLastChanged: new Date()
        });

        await newUser.save();

        // Audit log
        try {
            await Audit.create({
                userId: newUser._id,
                username: newUser.username,
                action: "Admin Registered",
                details: `Admin ${newUser.username} registered with role ${newUser.role}`
            });
        } catch (auditErr) {
            console.error("Audit log creation failed:", auditErr);
        }

        res.json({ message: "✅ Admin registered successfully. Please login." });
    } catch (error) {
        console.error("❌ Error in admin register:", error);
        res.status(500).json({ message: "Server error during registration." });
    }
});

// Login route for users
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).json({ message: "❌ Invalid email or password." });
        }

        if (user.isLocked()) {
            return res.status(403).json({
                message: "❌ Account temporarily locked due to multiple failed attempts. Try again in 5 minutes."
            });
        }

        user.lastAttempt = new Date();
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            await user.incrementLoginAttempts();

            if (user.isLocked()) {
                return res.status(403).json({
                    message: "❌ Account locked due to too many failed attempts. Try again in 5 minutes."
                });
            } else {
                const attemptsLeft = Math.max(5 - user.loginAttempts, 0);
                return res.status(401).json({
                    message: `❌ Invalid email or password. ${attemptsLeft} attempt(s) left.`
                });
            }
        }

        user.lastLogin = new Date();
        await user.resetLoginAttempts();

        // Audit log
        try {
            await Audit.create({
                userId: user._id,
                username: user.username,
                action: "User Logged In",
                details: `User ${user.username} logged in`
            });
        } catch (auditErr) {
            console.error("Audit log creation failed:", auditErr);
        }

        res.json({
            message: "✅ Login successful!",
            user: {
                _id: user._id,
                username: user.username,
                email: user.email,
                description: user.description,
                avatar: user.avatar,
                lastLogin: user.lastLogin,
                lastAttempt: user.lastAttempt,
                role: user.role
            }
        });
    } catch (err) {
        console.error("❌ Error logging in:", err);
        res.status(500).json({ message: "Error logging in." });
    }
});

// Admin login route
app.post("/admin/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const admin = await User.findOne({ email, role: { $in: ["admin", "roleA", "product_manager"] } });
        console.log("Login attempt for email:", email);
        console.log("Found admin user:", admin);

        if (!admin) {
            return res.status(401).json({ message: "❌ Invalid admin credentials." });
        }

        if (admin.isLocked()) {
            return res.status(403).json({
                message: "❌ Account temporarily locked due to multiple failed attempts. Try again in 5 minutes."
            });
        }

        admin.lastAttempt = new Date();
        const isMatch = await bcrypt.compare(password, admin.password);
        console.log("Password match:", isMatch);

        if (!isMatch) {
            await admin.incrementLoginAttempts();

            if (admin.isLocked()) {
                return res.status(403).json({
                    message: "❌ Account locked due to too many failed attempts. Try again in 5 minutes."
                });
            } else {
                const attemptsLeft = Math.max(5 - admin.loginAttempts, 0);
                return res.status(401).json({
                    message: `❌ Invalid admin credentials. ${attemptsLeft} attempt(s) left.`
                });
            }
        }

        admin.lastLogin = new Date();
        await admin.resetLoginAttempts();

        // Audit log
        try {
            await Audit.create({
                userId: admin._id,
                username: admin.username,
                action: "Admin Logged In",
                details: `Admin ${admin.username} logged in`
            });
        } catch (auditErr) {
            console.error("Audit log creation failed:", auditErr);
        }

        res.json({
            message: "✅ Admin login successful!",
            admin: {
                _id: admin._id,
                username: admin.username,
                email: admin.email,
                role: admin.role
            }
        });
    } catch (err) {
        console.error("❌ Error logging in admin:", err);
        res.status(500).json({ message: "Error logging in admin." });
    }
});

// Reviews routes
app.get("/reviews", async (req, res) => {
    try {
        const reviews = await Review.find();
        res.json(reviews);
    } catch (err) {
        res.status(500).json({ message: "Error fetching reviews." });
    }
});

app.post("/reviews", async (req, res) => {
    try {
        const { userId, username, branch, rating, text } = req.body;
        const review = new Review({ userId, username, branch, rating, text });
        await review.save();
        res.status(201).json({ message: "Review added." });
    } catch (err) {
        res.status(500).json({ message: "Error adding review." });
    }
});

app.put("/reviews/:id", async (req, res) => {
    try {
        const review = await Review.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!review) return res.status(404).json({ message: "Review not found." });
        res.json(review);
    } catch (err) {
        res.status(500).json({ message: "Error updating review." });
    }
});

app.delete("/reviews/:id", async (req, res) => {
    try {
        const review = await Review.findByIdAndDelete(req.params.id);
        if (!review) return res.status(404).json({ message: "Review not found." });
        res.json({ message: "Review deleted." });
    } catch (err) {
        res.status(500).json({ message: "Error deleting review." });
    }
});

// Middleware to check admin auth - placeholder
const adminCheck = (req, res, next) => {
    // TODO: Replace with real auth
    next();
};

// Admin get all users (merged Manage Accounts & Assign Roles) at /webcafe/users
app.get("/webcafe/users", adminCheck, async (req, res) => {
    try {
        const users = await User.find({}, "-password -passwordHistory");
        res.json(users);
    } catch (err) {
        res.status(500).json({ message: "Error fetching users." });
    }
});

// Get single user by ID (for edit)
app.get("/webcafe/users/:id", adminCheck, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("-password -passwordHistory");
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: "Error fetching user data." });
  }
});

// Admin update user general info (username, email, description)
app.put('/webcafe/users/:id', adminCheck, async (req, res) => {
  try {
    const allowedUpdatesForPM = ['username', 'email', 'description'];
    const allowedUpdatesForAdmin = ['username', 'email', 'description', 'role'];

    // The role of the requester (admin, product_manager, etc.)
    const requesterRole = req.user?.role || 'customer'; // Adjust based on your auth middleware

    // Determine allowed fields based on requester role
    const allowedUpdates = requesterRole === 'admin' ? allowedUpdatesForAdmin : allowedUpdatesForPM;

    // Check if user tries to update disallowed fields (like 'role' for PM)
    const updates = Object.keys(req.body);
    const invalidFields = updates.filter(field => !allowedUpdates.includes(field));
    if (invalidFields.length > 0) {
      return res.status(400).json({ message: `Invalid fields to update: ${invalidFields.join(', ')}` });
    }

    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Apply updates allowed for the requester
    updates.forEach(update => {
      user[update] = req.body[update];
    });

    await user.save();

    res.json({ message: 'User updated successfully', user });
  } catch (err) {
    console.error('Error updating user:', err);
    res.status(500).json({ message: 'Server error updating user' });
  }
});

// Admin update user role
app.put("/webcafe/users/:id/role", adminCheck, async (req, res) => {
    try {
        const { role } = req.body;
        const validRoles = ["customer", "admin", "roleA"];
        if (!validRoles.includes(role)) {
            return res.status(400).json({ message: "Invalid role." });
        }
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ message: "User not found." });

        user.role = role;
        await user.save();

        // Audit log for role change
        await Audit.create({
            userId: user._id,
            username: user.username,
            action: "Role Changed",
            details: `User ${user.username} role changed to ${role}`
        });

        res.json({ message: "User role updated." });
    } catch (err) {
        res.status(500).json({ message: "Error updating user role." });
    }
});

// Admin delete user account
app.delete("/webcafe/users/:id", adminCheck, async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) return res.status(404).json({ message: "User not found." });

        // Audit log user deletion
        await Audit.create({
            userId: user._id,
            username: user.username,
            action: "User Deleted",
            details: `User ${user.username} deleted`
        });

        res.json({ message: "User deleted." });
    } catch (err) {
        res.status(500).json({ message: "Error deleting user." });
    }
});

// Audit trail endpoint at /webcafe/audit
app.get("/webcafe/audit", async (req, res) => {
    try {
        const audits = await Audit.find().sort({ createdAt: -1 });
        res.json(audits);
    } catch (err) {
        res.status(500).json({ message: "Error fetching audit logs." });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});
