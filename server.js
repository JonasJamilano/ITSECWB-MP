const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const bcrypt = require("bcrypt");
const Audit = require("./Audit");
const adminUser = require('./adminUser');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// Serve static files from current directory and uploads folder
app.use(express.static(__dirname));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Serve Homepage.html at root
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "Homepage.html"));
});

// MongoDB Connection
mongoose.connect("mongodb://localhost:27017/webcafe", {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log("✅ Connected to MongoDB"))
.catch(err => console.log("❌ MongoDB Connection Error:", err));

// User Schema with role field added
const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String,
    passwordHistory: [String],
    passwordLastChanged: { type: Date, default: Date.now },
    firstName: String,
    lastName: String,
    description: String,
    avatar: String,
    loginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date },
    lastLogin: { type: Date },
    lastAttempt: { type: Date },
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
            this.lockUntil = new Date(Date.now() + 5 * 60 * 1000);
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

// Review Schema
const reviewSchema = new mongoose.Schema({
    userId: String,
    username: String,
    branch: String,
    rating: Number,
    text: String,
    date: { type: Date, default: Date.now }
});
const Review = mongoose.model("Review", reviewSchema);

// Multer Setup for File Uploads
const storage = multer.diskStorage({
    destination: path.join(__dirname, "uploads"),
    filename: (req, file, cb) => {
        cb(null, Date.now() + "-" + file.originalname);
    }
});
const upload = multer({ storage });

// Register Route for regular users
app.post("/register", upload.single("avatar"), async (req, res) => {
    try {
        const { username, email, password, description } = req.body;
        const avatar = req.file ? "/uploads/" + req.file.filename : null;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "❌ Email already registered." });
        }

        const complexityRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!complexityRegex.test(password)) {
            return res.status(400).json({
                message: "❌ Password must be at least 8 characters and include uppercase, lowercase, a number, and a special character."
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

        try {
            await Audit.create({
                userId: newUser._id,
                username: newUser.username,
                action: "User Registered",
                details: `User ${newUser.username} registered with role ${newUser.role}`
            });
            console.log(`Audit log created for user registration: ${newUser.username}`);
        } catch (auditErr) {
            console.error("Audit log creation failed:", auditErr);
        }

        console.log(`User registered successfully: ${username}`);
        res.json({ message: "✅ User registered successfully!" });
    } catch (err) {
        console.error("❌ Error in registration:", err);
        res.status(500).json({ message: "Error registering user." });
    }
});



// New Admin Register Route with role selection
app.post("/admin/register", multer().none(), async (req, res) => {
    try {
        const { username, email, password, role } = req.body;

        console.log("Admin registration attempt:", { username, email, role });

        if (!username || !email || !password || !role) {
            return res.status(400).json({ message: "All fields are required." });
        }

        const validRoles = ["admin", "roleA"];
        if (!validRoles.includes(role)) {
            return res.status(400).json({ message: "Invalid role." });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "Email already registered." });
        }

        const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;
        if (!regex.test(password)) {
            return res.status(400).json({
                message: "Password must be at least 8 chars, with uppercase, lowercase, number and special char.",
            });
        }

        const hashed = await bcrypt.hash(password, 10);

        const newUser = new User({
            username,
            email,
            password: hashed,
            role,
            passwordLastChanged: new Date(),
        });

        await newUser.save();

        try {
            await Audit.create({
                userId: newUser._id,
                username: newUser.username,
                action: "Admin Registered",
                details: `Admin ${newUser.username} registered with role ${newUser.role}`
            });
            console.log("Audit log created for new admin registration.");
        } catch (auditErr) {
            console.error("Audit log creation failed:", auditErr);
        }

        console.log(`Admin registered successfully: ${username}`);
        res.json({ message: "✅ Admin registered successfully. Please login." });
    } catch (error) {
        console.error("❌ Error in admin register:", error);
        res.status(500).json({ message: "Server error during registration." });
    }
});

// Login Route for users
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
            const attemptsLeft = Math.max(5 - user.loginAttempts, 0);

            if (user.isLocked()) {
                return res.status(403).json({
                    message: "❌ Account locked due to too many failed attempts. Try again in 5 minutes."
                });
            } else {
                return res.status(401).json({
                    message: `❌ Invalid email or password. ${attemptsLeft} attempt(s) left.`
                });
            }
        }

        user.lastLogin = new Date();
        await user.resetLoginAttempts();

        try {
            await Audit.create({
                userId: user._id,
                username: user.username,
                action: "User Logged In",
                details: `User ${user.username} logged in`
            });
            console.log(`Audit log created for user login: ${user.username}`);
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

// Password Reset Route (unchanged placeholder)
app.post('/reset-password', async (req, res) => {
    res.status(501).json({ message: "Password reset route not implemented." });
});

// Change password route (logged-in user) (placeholder)
app.put("/change-password/:id", async (req, res) => {
    res.status(501).json({ message: "Change password route not implemented." });
});

// Update Profile (placeholder)
app.put("/update-profile/:id", async (req, res) => {
    res.status(501).json({ message: "Update profile route not implemented." });
});

// Update Avatar (placeholder)
app.put("/update-avatar/:id", upload.single("avatar"), async (req, res) => {
    res.status(501).json({ message: "Update avatar route not implemented." });
});

// Reviews routes (basic examples)
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

// Admin Login Route
app.post("/admin/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const admin = await User.findOne({ email, role: "admin" });

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

        if (!isMatch) {
            await admin.incrementLoginAttempts();
            const attemptsLeft = Math.max(5 - admin.loginAttempts, 0);

            if (admin.isLocked()) {
                return res.status(403).json({
                    message: "❌ Account locked due to too many failed attempts. Try again in 5 minutes."
                });
            } else {
                return res.status(401).json({
                    message: `❌ Invalid admin credentials. ${attemptsLeft} attempt(s) left.`
                });
            }
        }

        admin.lastLogin = new Date();
        await admin.resetLoginAttempts();

        try {
            await Audit.create({
                userId: admin._id,
                username: admin.username,
                action: "Admin Logged In",
                details: `Admin ${admin.username} logged in`
            });
            console.log(`Audit log created for admin login: ${admin.username}`);
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

// Admin can fetch all users (excluding passwords)
app.get("/admin/users", async (req, res) => {
    try {
        const users = await User.find({}, "-password -passwordHistory");
        res.json(users);
    } catch (err) {
        res.status(500).json({ message: "Error fetching users." });
    }
});

// Admin can delete user by id
app.delete("/admin/users/:id", async (req, res) => {
    try {
        const deletedUser = await User.findByIdAndDelete(req.params.id);

        if (!deletedUser) {
            return res.status(404).json({ message: "User not found." });
        }

        try {
            await Audit.create({
                userId: deletedUser._id,
                username: deletedUser.username,
                action: "User Deleted",
                details: `User ${deletedUser.username} deleted by admin`
            });
            console.log(`Audit log created for deleted user: ${deletedUser.username}`);
        } catch (auditErr) {
            console.error("Audit log creation failed:", auditErr);
        }

        res.json({ message: "User deleted successfully." });
    } catch (err) {
        res.status(500).json({ message: "Error deleting user." });
    }
});

// Admin can assign roles to user
app.put("/admin/users/:id/role", async (req, res) => {
    try {
        const { role } = req.body;
        const validRoles = ["customer", "admin", "roleA"];

        if (!validRoles.includes(role)) {
            return res.status(400).json({ message: "Invalid role." });
        }

        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        user.role = role;
        await user.save();

        try {
            await Audit.create({
                userId: user._id,
                username: user.username,
                action: "Role Changed",
                details: `User ${user.username} role changed to ${role}`
            });
            console.log(`Audit log created for role change: ${user.username} -> ${role}`);
        } catch (auditErr) {
            console.error("Audit log creation failed:", auditErr);
        }

        res.json({ message: `User role updated to ${role}` });
    } catch (err) {
        res.status(500).json({ message: "Error updating user role." });
    }
});

// Audit Trail - Get all audit logs
app.get("/admin/audit", async (req, res) => {
    try {
        const audits = await Audit.find().sort({ timestamp: -1 });
        res.json(audits);
    } catch (err) {
        res.status(500).json({ message: "Error fetching audit logs." });
    }
});

// Start Server
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
