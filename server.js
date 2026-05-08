import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import ImageKit from "imagekit";
import multer from "multer";
import crypto from "crypto";
import { Resend } from "resend";

dotenv.config();
const resend = new Resend(process.env.RESEND_API_KEY);

const app = express();
const PORT = process.env.PORT || 3001;

const storage = multer.memoryStorage();
const upload = multer({ storage });

// Middleware

const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",").map((origin) => origin.trim())
  : [];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

app.use(express.json());

const imagekit = new ImageKit({
  publicKey: process.env.IMAGEKIT_PUBLIC,
  privateKey: process.env.IMAGEKIT_PRIVATE,
  urlEndpoint: process.env.IMAGEKIT_URL_ENDPOINT,
});

async function sendOtpEmail({ to, firstName, otp }) {
  try {
    await resend.emails.send({
      from: "BankApp <onboarding@resend.dev>", // or your verified domain
      to,
      subject: "Your OTP Code",
      html: `
        <div style="font-family: Arial, sans-serif">
          <h2>Hello ${firstName},</h2>
          <p>Your OTP code is:</p>
          <h1 style="letter-spacing: 4px">${otp}</h1>
          <p>This code expires in <strong>5 minutes</strong>.</p>
        </div>
      `,
    });

    return true;
  } catch (err) {
    console.error("Resend OTP error:", err);
    return false;
  }
}

// MongoDB connection
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  phone: String,
  dateOfBirth: Date,
  address: {
    street: String,
    city: String,
    state: String,
    zipCode: String,
  },
  awcCode: { type: String, unique: true }, // <-- NEW
  avatar: { type: String }, // 🔹 Store ImageKit URL
  role: { type: String, enum: ["user", "admin"], default: "user" }, // ✅ added role
  otp: String,
  otpExpires: Date,
  transactionOtp: { type: String },
  transactionOtpExpires: { type: Date },
  createdAt: { type: Date, default: Date.now },
});

// Account Schema
const accountSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  accountNumber: { type: String, required: true, unique: true },
  accountType: {
    type: String,
    enum: ["checking"],
    required: true,
  },
  balance: { type: Number, default: 0 },
  status: {
    type: String,
    enum: ["active", "inactive", "frozen"],
    default: "active",
  },
  createdAt: { type: Date, default: Date.now },
});

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  accountId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Account",
    required: true,
  },
  type: {
    type: String,
    enum: ["deposit", "withdrawal", "transfer", "payment", "crypto"],
    required: true,
  },
  amount: {
    type: Number,
    required: true,
  },
  description: String,

  // Fiat payments
  recipientAccount: String,
  recipientName: String,

  // Crypto-specific fields
  cryptoType: {
    type: String,
    enum: ["BTC", "ETH", "USDT"],
    required: function () {
      return this.type === "crypto";
    },
  },
  recipientAddress: {
    type: String,
    required: function () {
      return this.type === "crypto";
    },
  },
  networkFee: {
    type: Number, // store numeric fee in same currency as amount
    required: false,
  },
  network: {
    type: String, // e.g. "Ethereum", "Tron", "Bitcoin mainnet"
    required: false,
  },

  status: {
    type: String,
    enum: ["pending", "completed", "failed"],
    default: "completed",
  },
  date: { type: Date, default: Date.now },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Card Schema
const cardSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  accountId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Account",
    required: true,
  },
  cardNumber: { type: String, required: true },
  cardType: { type: String, enum: ["debit", "credit"], required: true },
  expiryDate: { type: String, required: true },
  cvv: { type: String, required: true },
  status: {
    type: String,
    enum: ["active", "blocked", "expired"],
    default: "active",
  },
  creditLimit: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const Account = mongoose.model("Account", accountSchema);
const Transaction = mongoose.model("Transaction", transactionSchema);
const Card = mongoose.model("Card", cardSchema);

// Virtual populate for accounts
userSchema.virtual("accounts", {
  ref: "Account",
  localField: "_id",
  foreignField: "userId",
});

userSchema.set("toJSON", { virtuals: true });
userSchema.set("toObject", { virtuals: true });

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(
    token,
    process.env.JWT_SECRET || "banking_secret_key",
    (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    },
  );
};

function adminMiddleware(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({ message: "Access denied" });
  }
  next();
}

// Generate account number
const generateAccountNumber = () => {
  return (
    "9532" +
    Math.floor(Math.random() * 100000000)
      .toString()
      .padStart(8, "0")
  );
};

// Generate card number
const generateCardNumber = () => {
  return (
    "4532" +
    Math.floor(Math.random() * 1000000000000)
      .toString()
      .padStart(12, "0")
  );
};

function generateAWCCode() {
  const randomPart = Math.random().toString(36).substring(2, 8).toUpperCase();
  return `AWC-${randomPart}`;
}

// Auth routes
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, firstName, lastName, phone } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const awcCode = generateAWCCode();

    const user = new User({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      phone,
      role: "user",
      awcCode,
    });
    await user.save();

    // Create default checking + savings + card
    const checkingAccount = new Account({
      userId: user._id,
      accountNumber: generateAccountNumber(),
      accountType: "checking",
      balance: 0,
    });
    await checkingAccount.save();

    // const savingsAccount = new Account({
    //   userId: user._id,
    //   accountNumber: generateAccountNumber(),
    //   accountType: "savings",
    //   balance: 0,
    // });
    // await savingsAccount.save();

    const debitCard = new Card({
      userId: user._id,
      accountId: checkingAccount._id,
      cardNumber: generateCardNumber(),
      cardType: "debit",
      expiryDate: "12/28",
      cvv: Math.floor(Math.random() * 1000)
        .toString()
        .padStart(3, "0"),
    });
    await debitCard.save();

    // Generate OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    user.otp = otp;
    user.otpExpires = Date.now() + 5 * 60 * 1000; // 5 min
    await user.save();

    const sent = await sendOtpEmail({
      to: user.email,
      firstName: user.firstName,
      otp,
    });

    if (!sent) {
      return res.status(503).json({
        message: "Unable to send OTP at the moment. Please try again.",
      });
    }

    res.status(201).json({
      message:
        "User registered. OTP sent to your email. Please verify to activate your account.",
    });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials" });

    // generate OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    user.otp = otp;
    user.otpExpires = Date.now() + 5 * 60 * 1000; // 5 min expiry
    await user.save();

    // send OTP via email
    const sent = await sendOtpEmail({
      to: user.email,
      firstName: user.firstName,
      otp,
    });

    if (!sent) {
      return res.status(503).json({
        message: "Unable to send OTP at the moment. Please try again.",
      });
    }

    res.json({ message: "OTP sent to your email" });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/auth/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    if (user.otp !== otp || Date.now() > user.otpExpires) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    // clear OTP
    user.otp = null;
    user.otpExpires = null;
    await user.save();

    // issue JWT
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET || "banking_secret_key",
      { expiresIn: "1h" },
    );

    res.json({
      message: "OTP verified successfully",
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        awcCode: user.awcCode,
      },
    });
  } catch (error) {
    console.error("OTP verify error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/auth/resend-otp", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    // generate OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    user.otp = otp;
    user.otpExpires = Date.now() + 5 * 60 * 1000;
    await user.save();

    // send OTP email
    const sent = await sendOtpEmail({
      to: user.email,
      firstName: user.firstName,
      otp,
    });

    if (!sent) {
      return res.status(503).json({
        message: "Unable to send OTP at the moment. Please try again.",
      });
    }

    res.json({ message: "New OTP sent to your email" });
  } catch (error) {
    console.error("Resend OTP error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Account routes
app.get("/api/accounts", authenticateToken, async (req, res) => {
  try {
    const accounts = await Account.find({ userId: req.user.userId });
    res.json(accounts);
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Transaction routes
app.get("/api/transactions", authenticateToken, async (req, res) => {
  try {
    const transactions = await Transaction.find({ userId: req.user.userId })
      .sort({ createdAt: -1 })
      .limit(50);
    res.json(transactions);
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/transactions/transfer", authenticateToken, async (req, res) => {
  try {
    const {
      otp,
      fromAccountId,
      toAccount, // for fiat transfers (account number / IBAN)
      amount,
      description,
      transferType, // "internal" | "swift" | "sepa" | "crypto"
      cryptoType, // required if crypto
      recipientAddress, // required if crypto
      networkFee, // optional for crypto
      network, // optional for crypto (Ethereum, Bitcoin,
    } = req.body; // Add otp to destructuring

    const user = await User.findById(req.user.userId);

    // Verify OTP
    if (
      !user.transactionOtp ||
      user.transactionOtp !== otp ||
      Date.now() > user.transactionOtpExpires
    ) {
      return res
        .status(401)
        .json({ message: "Invalid or expired security code" });
    }

    // Clear OTP after use so it can't be reused
    user.transactionOtp = undefined;
    user.transactionOtpExpires = undefined;
    await user.save();

    // Validate sender account
    const fromAccount = await Account.findOne({
      _id: fromAccountId,
      userId: req.user.userId,
    });

    if (!fromAccount || fromAccount.balance < amount) {
      return res.status(400).json({ message: "Insufficient funds" });
    }

    // Deduct from sender
    await Account.findByIdAndUpdate(fromAccountId, {
      $inc: { balance: -amount },
    });

    let toAccountDoc = null;
    let transactionPayload = {
      userId: req.user.userId,
      accountId: fromAccountId,
      amount,
      description: description || "Money Transfer",
      status: "completed",
    };

    if (transferType === "internal") {
      // Find recipient account inside same user
      toAccountDoc = await Account.findOne({
        accountNumber: toAccount,
        userId: req.user.userId,
      });

      if (!toAccountDoc) {
        return res.status(404).json({ message: "Recipient account not found" });
      }

      // Add to recipient balance
      await Account.findByIdAndUpdate(toAccountDoc._id, {
        $inc: { balance: amount },
      });

      transactionPayload = {
        ...transactionPayload,
        type: "transfer",
        recipientAccount: toAccount,
      };
    } else if (transferType === "crypto") {
      // Crypto transfer – don’t look for internal account
      if (!cryptoType || !recipientAddress) {
        return res
          .status(400)
          .json({ message: "Crypto type and recipient address are required" });
      }

      transactionPayload = {
        ...transactionPayload,
        type: "crypto",
        cryptoType,
        recipientAddress,
        networkFee: networkFee || 0,
        network: network || null,
      };
    } else {
      // External fiat transfer (SWIFT / SEPA)
      transactionPayload = {
        ...transactionPayload,
        type: "transfer",
        recipientAccount: toAccount,
      };
    }

    // Save transaction
    const transaction = new Transaction(transactionPayload);
    await transaction.save();

    res.json({
      message: "Transfer completed successfully",
      transaction,
      updatedFrom: fromAccountId,
      updatedTo: toAccountDoc?._id || null,
    });
  } catch (error) {
    console.error("Transfer error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// POST /api/transactions/request-otp
app.post(
  "/api/transactions/request-otp",
  authenticateToken,
  async (req, res) => {
    try {
      const user = await User.findById(req.user.userId);

      // 1. Generate a 6-digit numeric OTP
      const otp = Math.floor(100000 + Math.random() * 900000).toString();

      // 2. Save to user with 5-minute expiry
      user.transactionOtp = otp;
      user.transactionOtpExpires = Date.now() + 5 * 60 * 1000;
      await user.save();

      // 3. Send via Resend
      const sent = await sendOtpEmail({
        to: user.email,
        firstName: user.firstName,
        otp,
      });

      if (!sent)
        return res.status(500).json({ message: "Email service failed" });

      res.json({ message: "OTP sent to your email" });
    } catch (error) {
      res.status(500).json({ message: "Error sending OTP" });
    }
  },
);

// Card routes
app.get("/api/cards", authenticateToken, async (req, res) => {
  try {
    const cards = await Card.find({ userId: req.user.userId }).populate(
      "accountId",
    );
    res.json(cards);
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Dashboard stats
app.get("/api/dashboard/stats", authenticateToken, async (req, res) => {
  try {
    const accounts = await Account.find({ userId: req.user.userId });
    const transactions = await Transaction.find({ userId: req.user.userId })
      .sort({ createdAt: -1 })
      .limit(10);

    const totalBalance = accounts.reduce(
      (sum, account) => sum + account.balance,
      0,
    );
    const monthlySpending = await Transaction.aggregate([
      {
        $match: {
          userId: new mongoose.Types.ObjectId(req.user.userId),
          type: { $in: ["withdrawal", "payment", "transfer"] },
          createdAt: {
            $gte: new Date(new Date().getFullYear(), new Date().getMonth(), 1),
          },
        },
      },
      {
        $group: {
          _id: null,
          total: { $sum: "$amount" },
        },
      },
    ]);

    res.json({
      totalBalance,
      accountCount: accounts.length,
      monthlySpending: Math.abs(monthlySpending[0]?.total || 0),
      recentTransactions: transactions,
    });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Profile routes
app.put("/api/user/profile", authenticateToken, async (req, res) => {
  try {
    const { firstName, lastName, phone, dateOfBirth, address } = req.body;

    const updatedUser = await User.findByIdAndUpdate(
      req.user.userId,
      {
        firstName,
        lastName,
        phone,
        dateOfBirth,
        address,
      },
      { new: true, runValidators: true },
    ).select("-password");

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(updatedUser);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Failed to update profile", error: error.message });
  }
});

app.put("/api/user/change-password", authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Current password is incorrect" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ message: "Password updated successfully" });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Failed to change password", error: error.message });
  }
});

// Get current user's profile
app.get("/api/user/profile", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(user);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Failed to fetch profile", error: error.message });
  }
});

app.post(
  "/api/upload-avatar",
  authenticateToken,
  upload.single("avatar"), // must match FormData key
  async (req, res) => {
    try {
      const userId = req.user.userId;

      if (!req.file) {
        return res
          .status(400)
          .json({ success: false, message: "No file uploaded" });
      }
      const uploadedImage = await imagekit.upload({
        file: req.file.buffer, // buffer works because memoryStorage
        fileName: `${userId}-avatar.jpg`,
        folder: "/avatars",
      });

      const updatedUser = await User.findByIdAndUpdate(
        userId,
        { avatar: uploadedImage.url },
        { new: true },
      );

      res.json({ success: true, avatar: updatedUser.avatar });
    } catch (error) {
      console.error("Upload error:", error);
      res.status(500).json({ success: false, message: "Avatar upload failed" });
    }
  },
);

app.patch(
  "/api/admin/accounts/:id",
  authenticateToken,
  adminMiddleware,
  async (req, res) => {
    try {
      const { balance } = req.body;
      const account = await Account.findByIdAndUpdate(
        req.params.id,
        { balance },
        { new: true },
      );
      if (!account)
        return res.status(404).json({ message: "Account not found" });
      res.json(account);
    } catch (err) {
      res
        .status(500)
        .json({ message: "Error updating account", error: err.message });
    }
  },
);

app.post(
  "/api/admin/transactions",
  authenticateToken,
  adminMiddleware,
  async (req, res) => {
    try {
      // 1. Added 'date' to the destructuring
      const { userId, accountId, type, amount, description, date } = req.body;

      const account = await Account.findById(accountId);
      if (!account) {
        return res.status(404).json({ message: "Account not found" });
      }

      if (type === "deposit") {
        account.balance += Number(amount);
      } else if (["withdrawal", "payment", "transfer"].includes(type)) {
        if (account.balance < amount) {
          return res.status(400).json({ message: "Insufficient funds" });
        }
        account.balance -= Number(amount);
      }

      await account.save();

      // 2. Pass the date to the Transaction constructor
      const transaction = new Transaction({
        userId,
        accountId,
        type,
        amount,
        description,
        date: date || new Date(), // Fallback to current date if empty
        status: "completed",
      });

      await transaction.save();

      res.status(201).json({
        message: "Transaction added",
        transaction,
        updatedBalance: account.balance,
      });
    } catch (err) {
      res
        .status(500)
        .json({ message: "Error creating transaction", error: err.message });
    }
  },
);

// =================== GET USERS WITH ACCOUNTS + TRANSACTIONS ===================
app.get(
  "/api/admin/users",
  authenticateToken,
  adminMiddleware,
  async (req, res) => {
    try {
      // Get all users
      const users = await User.find().lean();
      // Get all accounts
      const accounts = await Account.find().lean();

      // Get all transactions
      const transactions = await Transaction.find().lean();

      // Merge accounts + transactions into each user
      const usersWithAccounts = users.map((user) => {
        const userAccounts = accounts.filter(
          (acc) => acc.userId.toString() === user._id.toString(),
        );

        // Attach transactions for each account
        const accountsWithTx = userAccounts.map((acc) => ({
          ...acc,
          transactions: transactions.filter(
            (tx) => tx.accountId.toString() === acc._id.toString(),
          ),
        }));

        return {
          ...user,
          accounts: accountsWithTx,
        };
      });

      res.json(usersWithAccounts);
    } catch (err) {
      console.error("Error fetching users:", err);
      res
        .status(500)
        .json({ message: "Error fetching users", error: err.message });
    }
  },
);

// =================== DELETE TRANSACTION ===================
app.delete(
  "/api/admin/transactions/:id",
  authenticateToken,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;

      // Find the transaction
      const transaction = await Transaction.findById(id);
      if (!transaction) {
        return res.status(404).json({ message: "Transaction not found" });
      }

      // Find related account
      const account = await Account.findById(transaction.accountId);
      if (!account) {
        return res.status(404).json({ message: "Account not found" });
      }

      const amount = Number(transaction.amount);

      // Reverse balance effect
      if (transaction.type === "deposit") {
        account.balance -= amount;
      } else if (
        transaction.type === "withdrawal" ||
        transaction.type === "payment"
      ) {
        account.balance += amount;
      } else if (transaction.type === "transfer") {
        account.balance += amount;
      }

      await account.save();

      // Delete the transaction
      await transaction.deleteOne();

      res.json({
        message: "Transaction deleted and balance reverted",
        updatedBalance: account.balance,
      });
    } catch (err) {
      res.status(500).json({
        message: "Error deleting transaction",
        error: err.message,
      });
    }
  },
);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
