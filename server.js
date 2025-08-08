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
app.use(express.static(path.join(__dirname)));
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
    passwordHistory: [String], // hashes of past passwords
    passwordLastChanged: { type: Date, default: Date.now },
    firstName: String,
    lastName: String,
    description: String,
    avatar: String,
    loginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date },
    lastLogin: { type: Date }, // Last successful login
    lastAttempt: { type: Date } // Last attempt (success or fail)
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
            passwordLastChanged: new Date(), // ✅ Set time
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
  
      if (user.isLocked()) {
        return res.status(403).json({
          message: "❌ Account temporarily locked due to multiple failed attempts. Try again in 5 minutes."
        });
      }
  
      user.lastAttempt = new Date(); // ✅ Track every attempt
      const isMatch = await bcrypt.compare(password, user.password);
  
      if (!isMatch) {
        await user.incrementLoginAttempts(); // Increments and saves
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
  
            // Successful login
        user.lastLogin = new Date();               // ✅ Set lastLogin BEFORE save
        await user.resetLoginAttempts();           // ✅ Will save lastLogin too
  
        res.json({
        message: "✅ Login successful!",
        user: {
          _id: user._id,
          username: user.username,
          email: user.email,
          description: user.description,
          avatar: user.avatar,
          lastLogin: user.lastLogin,
          lastAttempt: user.lastAttempt
        }
      });
  
    } catch (err) {
      console.error("❌ Error logging in:", err);
      res.status(500).json({ message: "Error logging in." });
    }
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
  
      // 🔁 Compare with current and previous passwords
      const usedBefore = await Promise.any([
        bcrypt.compare(newPassword, user.password),
        ...(user.passwordHistory || []).map(oldHash => bcrypt.compare(newPassword, oldHash))
      ]).catch(() => false);
  
      if (usedBefore) {
        return res.status(400).json({
          message: '⚠️ You’ve used this password before. Please choose a new one.'
        });
      }
  
        // 🕒 Check if current password is less than 24 hours old
        const now = new Date();
        const lastChanged = user.passwordLastChanged || new Date(0);
        const hoursSinceLastChange = (now - lastChanged) / (1000 * 60 * 60);

        if (hoursSinceLastChange < 24) {
            const remainingTime = 24 - hoursSinceLastChange;
            const remainingHours = Math.floor(remainingTime);
            const remainingMinutes = Math.round((remainingTime - remainingHours) * 60);
            
            let timeMessage = '';
            if (remainingHours > 0) timeMessage += `${remainingHours} hour(s) `;
            if (remainingMinutes > 0) timeMessage += `${remainingMinutes} minute(s)`;
            
            return res.status(403).json({
                message: `⏳ You can’t change your password yet. Please wait ${timeMessage.trim()}.`
            });
        }
        
      // ✅ Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);
  
      // 🧠 Add current password to history
      const history = user.passwordHistory || [];
      history.unshift(user.password); // Add current to top
  
      if (history.length > 5) {
        history.pop(); // Keep only last 5
      }
  
      // 💾 Save new password + updated fields
      user.password = hashedPassword;
      user.passwordHistory = history;
      user.passwordLastChanged = new Date(); // ✅ Update timestamp
  
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

    // 🕒 Check if password is less than 24 hours old
    const now = new Date();
    const lastChanged = user.passwordLastChanged || new Date(0);
    const hoursSinceLastChange = (now - lastChanged) / (1000 * 60 * 60);

    if (hoursSinceLastChange < 24) {
      const remainingMs = (24 - hoursSinceLastChange) * 60 * 60 * 1000;
      const remainingHours = Math.floor(remainingMs / (1000 * 60 * 60));
      const remainingMinutes = Math.floor((remainingMs % (1000 * 60 * 60)) / (1000 * 60));

      return res.status(403).json({
        success: false,
        message: `⏳ You can’t change your password yet. Please wait ${remainingHours} hour(s) and ${remainingMinutes} minute(s).`
      });
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
