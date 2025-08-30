require("dotenv").config();
const express = require("express"),
  cors = require("cors"),
  jwt = require("jsonwebtoken"),
  bcrypt = require("bcryptjs"),
  mongoose = require("mongoose"),
  app = express(),
  PORT = process.env.PORT || 3001,
  JWT_SECRET = process.env.JWT_SECRET || "your_secret_key_here",
  JWT_EXPIRATION_TIME = "15d",
  saltRounds = 10,
  ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin",
  ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "adminpass";

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch((e) => console.error("❌ MongoDB connection error:", e));

const userSchema = new mongoose.Schema({
  name: String,
  email: {
    type: String,
    unique: true
  },
  password: String,
  role: {
    type: String,
    default: "user"
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
});
const User = mongoose.model("User", userSchema);

const valueSchema = new mongoose.Schema({
  name: String,
  imageUrl: String,
});
const selectionSchema = new mongoose.Schema({
  name: String,
  values: [valueSchema],
});
const productSchema = new mongoose.Schema({
  name: {
    type: String,
    unique: true
  },
  price: Number,
  category: String,
  description: String,
  stock: Number,
  image: String,
  smallImages: [String],
  selections: [selectionSchema],
  createdAt: {
    type: Date,
    default: Date.now
  },
});
const Product = mongoose.model("Product", productSchema);

const orderItemSchema = new mongoose.Schema({
  _id: mongoose.Schema.Types.ObjectId,
  name: String,
  price: Number,
  quantity: Number,
  image: String,
  selections: Object,
});

const orderSchema = new mongoose.Schema({
  user: {
    name: String,
    email: String
  },
  items: [orderItemSchema],
  shipping: Object,
  payment: {
    method: String,
    status: String
  },
  total: Number,
  createdAt: {
    type: Date,
    default: Date.now
  },
});
const Order = mongoose.model("Order", orderSchema);

function authenticateToken(e, s, t) {
  let a = e.headers.authorization,
    r = a && a.split(" ")[1];
  if (!r) return s.status(401).json({
    message: "Authentication token required."
  });
  jwt.verify(r, JWT_SECRET, (a, r) => {
    if (a) return s.status(403).json({
      message: "Invalid or expired token."
    });
    e.user = r, t();
  });
}
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

app.post("/api/register", async (e, s) => {
  let {
    name: t,
    email: a,
    password: r
  } = e.body;
  if (!t || !a || !r) return s.status(400).json({
    success: !1,
    message: "All fields are required."
  });
  try {
    if (await User.findOne({
        email: a
      })) return s.status(409).json({
      success: !1,
      message: "Email already registered."
    });
    let n;
    await new User({
      name: t,
      email: a,
      password: await bcrypt.hash(r, 10)
    }).save(), s.status(201).json({
      success: !0,
      message: "Registration successful!"
    });
  } catch (o) {
    console.error(o), s.status(500).json({
      success: !1,
      message: "Server error."
    });
  }
});

app.post("/api/login", async (e, s) => {
  let {
    email: t,
    password: a
  } = e.body;
  if (t === ADMIN_USERNAME && a === ADMIN_PASSWORD) {
    let r = {
        email: ADMIN_USERNAME,
        role: "admin",
        name: "Admin"
      },
      n = jwt.sign(r, JWT_SECRET, {
        expiresIn: "15d"
      });
    return s.json({
      success: !0,
      token: n,
      expires_in: "15d",
      user: r
    });
  }
  try {
    let o = await User.findOne({
      email: t
    });
    if (!o) return s.status(401).json({
      success: !1,
      message: "Invalid credentials"
    });
    if (!await bcrypt.compare(a, o.password)) return s.status(401).json({
      success: !1,
      message: "Invalid credentials"
    });
    let c = {
        email: o.email,
        name: o.name,
        role: o.role
      },
      i = jwt.sign(c, JWT_SECRET, {
        expiresIn: "15d"
      });
    s.json({
      success: !0,
      token: i,
      expires_in: "15d",
      user: c
    });
  } catch (u) {
    s.status(500).json({
      success: !1,
      message: "Server error."
    });
  }
});

app.get("/api/products", async (e, s) => {
  try {
    let {
      category: t,
      minPrice: a,
      maxPrice: r,
      name: n
    } = e.query, o = {};
    t && (o.category = t), (a || r) && (o.price = {}, a && (o.price.$gte = parseFloat(a)), r && (o.price.$lte = parseFloat(r))), n && (o.name = RegExp(n, "i"));
    let c = await Product.find(o);
    s.json(c);
  } catch (i) {
    s.status(500).json({
      error: "Server error"
    });
  }
});

app.post("/api/checkout", async (req, res) => {
  const {
    cartItems,
    shippingInfo,
    paymentInfo
  } = req.body;

  if (!cartItems || cartItems.length === 0) {
    return res.status(400).json({
      success: false,
      message: "Cart cannot be empty."
    });
  }

  if (!shippingInfo) {
    return res.status(400).json({
      success: false,
      message: "Shipping info required."
    });
  }

  // Identify the user or use a guest profile
  let user = {
    name: "Guest",
    email: "guest@example.com"
  };
  const token = req.headers.authorization?.split(" ")[1];
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      user = {
        name: decoded.name,
        email: decoded.email
      };
    } catch (e) {
      console.error("Invalid token, processing as guest.", e.message);
    }
  }

  try {
    // Collect all product IDs from the cart
    const productIds = cartItems.map(item => item._id);

    // Fetch all products from the database in one query
    const productsFromDb = await Product.find({
      _id: {
        $in: productIds
      }
    });

    const dbProductsMap = new Map();
    productsFromDb.forEach(p => {
      dbProductsMap.set(p._id.toString(), p);
    });

    const processedItems = [];
    let total = 0;

    for (const item of cartItems) {
      const dbProduct = dbProductsMap.get(item._id);

      // Validate the product exists
      if (!dbProduct) {
        return res.status(404).json({
          success: false,
          message: `Product with ID ${item._id} not found.`
        });
      }

      // Price validation using the backend price
      const verifiedPrice = dbProduct.price;

      processedItems.push({
        _id: dbProduct._id,
        name: item.name,
        price: verifiedPrice,
        quantity: item.quantity,
        image: dbProduct.image,
        selections: item.selectedOptions,
      });

      total += verifiedPrice * item.quantity;
    }

    // Create the order with the processed items
    const newOrder = new Order({
      user,
      items: processedItems,
      shipping: shippingInfo,
      payment: {
        method: paymentInfo?.method || "Not Specified",
        status: "Completed"
      },
      total,
    });

    await newOrder.save();

    res.status(201).json({
      success: true,
      message: "Checkout successful! Order placed.",
      orderId: newOrder._id,
    });
  } catch (err) {
    console.error("Checkout error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to place order."
    });
  }
});

app.post("/api/products", authenticateToken, async (e, s) => {
  if ("admin" !== e.user.role) return s.status(403).json({
    message: "Admin only."
  });
  try {
    let t = new Product(e.body);
    await t.save(), s.status(201).json({
      message: "Product added successfully"
    });
  } catch (a) {
    s.status(500).json({
      error: "Failed to add product"
    });
  }
});

app.delete("/api/products/:name", authenticateToken, async (e, s) => {
  if ("admin" !== e.user.role) return s.status(403).json({
    message: "Admin only."
  });
  try {
    let t = await Product.deleteOne({
      name: e.params.name
    });
    if (0 === t.deletedCount) return s.status(404).json({
      error: "Product not found"
    });
    s.json({
      message: "Product deleted successfully"
    });
  } catch (a) {
    s.status(500).json({
      error: "Failed to delete product"
    });
  }
});

// MODIFIED PUT ENDPOINT
app.put("/api/products/:name", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      message: "Admin only."
    });
  }
  try {
    const originalName = req.params.name;
    const updateData = req.body;

    // Use the original name from the URL params to find the product
    const product = await Product.findOneAndUpdate(
      { name: originalName },
      { $set: updateData }, // Use $set to update only the fields provided
      { new: true, runValidators: true } // Return the updated doc and run schema validators
    );

    if (!product) {
      return res.status(404).json({
        error: "Product not found"
      });
    }

    res.json({
      message: "Product updated successfully",
      product: product
    });
  } catch (err) {
    res.status(500).json({
      error: "Failed to update product"
    });
  }
});

app.get("/api/users", authenticateToken, async (e, s) => {
  if ("admin" !== e.user.role) return s.status(403).json({
    message: "Admin only."
  });
  try {
    let t = await User.find().select("-password");
    s.json(t);
  } catch (a) {
    s.status(500).json({
      success: !1,
      message: "Server error."
    });
  }
});

app.delete("/api/users/:email", authenticateToken, async (e, s) => {
  if ("admin" !== e.user.role) return s.status(403).json({
    message: "Admin only."
  });
  try {
    let t = await User.deleteOne({
      email: e.params.email
    });
    if (0 === t.deletedCount) return s.status(404).json({
      success: !1,
      message: "User not found."
    });
    s.json({
      success: !0,
      message: "User deleted successfully."
    });
  } catch (a) {
    s.status(500).json({
      success: !1,
      message: "Failed to delete user."
    });
  }
});

app.get("/api/orders", authenticateToken, async (e, s) => {
  if ("admin" !== e.user.role) return s.status(403).json({
    message: "Admin only."
  });
  try {
    let t = await Order.find();
    s.json(t);
  } catch (a) {
    s.status(500).json({
      success: !1,
      message: "Server error."
    });
  }
});

app.post("/api/logout", (e, s) => {
  s.json({
    success: !0,
    message: "Logged out successfully."
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});