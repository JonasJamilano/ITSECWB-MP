const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const bcrypt = require("bcrypt");
const adminRoutes = require("./adminUser"); // ✅ Import admin routes

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use("/uploads", express.static("uploads"));

// ✅ Mount admin API routes
app.use("/admin", adminRoutes);

// MongoDB Connection
mongoose.connect("mongodb://localhost:27017/webcafe", {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log("✅ Connected to MongoDB"))
.catch(err => console.log("❌ MongoDB Connection Error:", err));

// User Schema
const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String,
    firstName: String,
    lastName: String,
    description: String,
    website: String,
    facebook: String,
    twitter: String,
    avatar: String,
    loginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date }
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
            this.lockUntil = new Date(Date.now() + 5 * 60 * 1000); // Lock for 5 minutes
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
    destination: "./uploads",
    filename: (req, file, cb) => {
        cb(null, Date.now() + "-" + file.originalname);
    }
});
const upload = multer({ storage });

// Register Route
app.post("/register", upload.single("avatar"), async (req, res) => {
    try {
        const { username, email, password, description } = req.body;
        const avatar = req.file ? "/uploads/" + req.file.filename : null;

        // Check if email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "❌ Email already registered." });
        }

        // Password policy regex
        const complexityRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

if (!complexityRegex.test(password)) {
    return res.status(400).json({
        message: "❌ Password must be at least 8 characters and include uppercase, lowercase, a number, and a special character."
    });
}

        // ✅ Hash the password
        const hashedPassword = await bcrypt.hash(password, 10); // 10 is the salt rounds

        // Save the user with the hashed password
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
            description,
            avatar
        });

        await newUser.save();

        res.json({ message: "✅ User registered successfully!" });
    } catch (err) {
        console.error("❌ Error in registration:", err);
        res.status(500).json({ message: "Error registering user." });
    }
});

// Login Route
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).json({ message: "❌ Invalid email or password." });
        }

        // Check if account is locked
        if (user.isLocked()) {
            return res.status(403).json({
                message: "❌ Account temporarily locked due to multiple failed attempts. Try again in 5 minutes."
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            await user.incrementLoginAttempts();

            const freshUser = await User.findOne({ email }); // Re-fetch to get updated value
            const attemptsLeft = Math.max(5 - freshUser.loginAttempts, 0);

            if (freshUser.isLocked()) {
                return res.status(403).json({
                    message: "❌ Account locked due to too many failed attempts. Try again in 5 minutes."
                });
            } else {
                return res.status(401).json({
                    message: `❌ Invalid email or password. ${attemptsLeft} attempt(s) left.`
                });
            }
        }

        // Successful login — reset attempts
        await user.resetLoginAttempts();

        res.json({
            message: "✅ Login successful!",
            user: {
                _id: user._id,
                username: user.username,
                email: user.email,
                description: user.description,
                avatar: user.avatar
            }
        });

    } catch (err) {
        console.error("❌ Error logging in:", err);
        res.status(500).json({ message: "Error logging in." });
    }
});


// Update Profile
app.put("/update-profile/:id", async (req, res) => {
    try {
        const updatedFields = {
            email: req.body.email,
            username: req.body.username,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            description: req.body.description,
            website: req.body.website,
            facebook: req.body.facebook,
            twitter: req.body.twitter
        };

        const updatedUser = await User.findByIdAndUpdate(req.params.id, updatedFields, { new: true });

        if (!updatedUser) {
            return res.status(404).json({ message: "User not found" });
        }

        res.json({ message: "✅ Profile updated successfully!", user: updatedUser });
    } catch (error) {
        console.error("❌ Error updating profile:", error);
        res.status(500).json({ message: "Server error" });
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

// Reviews
app.get("/reviews", async (req, res) => {
    try {
        const { branch } = req.query;
        const reviews = await Review.find({ branch }).sort({ date: -1 });
        res.json(reviews);
    } catch (err) {
        res.status(500).json({ message: "Error fetching reviews." });
    }
});

app.post("/reviews", async (req, res) => {
    try {
        const { userId, username, branch, rating, text } = req.body;
        const newReview = new Review({ userId, username, branch, rating, text });
        await newReview.save();
        res.json({ message: "✅ Review added!", review: newReview });
    } catch (err) {
        res.status(500).json({ message: "Error submitting review." });
    }
});

app.put("/reviews/:id", async (req, res) => {
    try {
        const { text, rating } = req.body;
        const updatedReview = await Review.findByIdAndUpdate(req.params.id, { text, rating }, { new: true });

        if (!updatedReview) {
            return res.status(404).json({ message: "❌ Review not found." });
        }

        res.json({ message: "✅ Review updated!", review: updatedReview });
    } catch (err) {
        res.status(500).json({ message: "Error updating review." });
    }
});

app.delete("/reviews/:id", async (req, res) => {
    try {
        const deletedReview = await Review.findByIdAndDelete(req.params.id);
        if (!deletedReview) {
            return res.status(404).json({ message: "❌ Review not found." });
        }

        res.json({ message: "✅ Review deleted!" });
    } catch (err) {
        res.status(500).json({ message: "Error deleting review." });
    }
});

// Start Server
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
