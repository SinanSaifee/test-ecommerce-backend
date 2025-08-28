// --- LOAD ENVIRONMENT VARIABLES ---
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3001;

// --- SECRET KEY AND JWT EXPIRATION ---
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key_here';
const JWT_EXPIRATION_TIME = '15d';
const saltRounds = 10;

// --- ADMIN CREDENTIALS FROM .ENV ---
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'adminpass';

// --- MONGODB CONNECTION ---

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB Atlas'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// --- SCHEMAS & MODELS ---
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
    role: { type: String, default: 'user' },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// --- SCHEMAS & MODELS (Ensure these are correct) ---
const productSchema = new mongoose.Schema({
    name: { type: String, unique: true },
    price: Number,
    category: String,
    description: String,
    stock: Number,
    image: String, // Ensure the 'image' field is here
    createdAt: { type: Date, default: Date.now }
});
const Product = mongoose.model('Product', productSchema);

const orderSchema = new mongoose.Schema({
    user: {
        name: String,
        email: String,
    },
    items: [
        {
            _id: mongoose.Schema.Types.ObjectId,
            name: String,
            price: Number,
            quantity: Number,
            image: String, // Ensure the 'image' field is here to save the data
        }
    ],
    shipping: Object,
    payment: {
        method: String,
        status: String
    },
    total: Number,
    createdAt: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', orderSchema);


// --- MIDDLEWARE SETUP ---
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// --- AUTHENTICATION MIDDLEWARE ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Authentication token required.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or expired token.' });
        req.user = user;
        next();
    });
}

// =========================================================================
//                             API ENDPOINTS
// =========================================================================

// --- PUBLIC ROUTES: AUTHENTICATION AND PRODUCTS ---

// Register
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ success: false, message: 'Email already registered.' });
        }

        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ success: true, message: 'Registration successful!' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    // --- Admin login via .env credentials ---
    if (email === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        const user = { email: ADMIN_USERNAME, role: 'admin', name: 'Admin' };
        const accessToken = jwt.sign(user, JWT_SECRET, { expiresIn: JWT_EXPIRATION_TIME });
        return res.json({ success: true, token: accessToken, expires_in: JWT_EXPIRATION_TIME, user });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ success: false, message: 'Invalid credentials' });

        const payload = { email: user.email, name: user.name, role: user.role };
        const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRATION_TIME });

        res.json({ success: true, token: accessToken, expires_in: JWT_EXPIRATION_TIME, user: payload });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// Get products (with filters)
app.get('/api/products', async (req, res) => {
    try {
        const { category, minPrice, maxPrice, name } = req.query;
        let filter = {};
        if (category) filter.category = category;
        if (minPrice || maxPrice) filter.price = {};
        if (minPrice) filter.price.$gte = parseFloat(minPrice);
        if (maxPrice) filter.price.$lte = parseFloat(maxPrice);
        if (name) filter.name = new RegExp(name, 'i');

        const products = await Product.find(filter);
        res.json(products);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Checkout (guest or logged in)
// Checkout (guest or logged in)
app.post('/api/checkout', async (req, res) => {
    const { cartItems, shippingInfo, paymentInfo } = req.body;
    if (!cartItems || cartItems.length === 0) {
        return res.status(400).json({ success: false, message: 'Cart cannot be empty.' });
    }
    if (!shippingInfo) {
        return res.status(400).json({ success: false, message: 'Shipping info required.' });
    }

    // Determine user from token, or treat as guest
    let user = { name: 'Guest', email: 'guest@example.com' };
    const token = req.headers['authorization']?.split(' ')[1];
    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            user = { name: decoded.name, email: decoded.email };
        } catch (err) {
            console.error('Invalid token, processing as guest.', err.message);
        }
    }

    try {
        const productIds = cartItems.map(item => item._id);
        const productsFromDB = await Product.find({ '_id': { $in: productIds } });

        // Map products for quick lookup
        const dbProductsMap = new Map();
        productsFromDB.forEach(product => {
            dbProductsMap.set(product._id.toString(), product);
        });

        const validatedCartItems = [];
        let totalAmount = 0;

        for (const cartItem of cartItems) {
            const dbProduct = dbProductsMap.get(cartItem._id);
            if (!dbProduct) {
                return res.status(404).json({ success: false, message: `Product with ID ${cartItem._id} not found.` });
            }
            
            // Add the 'image' field from the fetched product to the validated item
            validatedCartItems.push({
                _id: dbProduct._id,
                name: dbProduct.name,
                price: dbProduct.price,
                quantity: cartItem.quantity,
                image: dbProduct.image // <-- This line is crucial for saving the image
            });
            
            totalAmount += dbProduct.price * cartItem.quantity;
        }

        const newOrder = new Order({
            user,
            items: validatedCartItems,
            shipping: shippingInfo,
            payment: {
                method: paymentInfo?.method || 'Not Specified',
                status: 'Completed'
            },
            total: totalAmount
        });

        await newOrder.save();
        res.status(201).json({ success: true, message: 'Checkout successful! Order placed.', orderId: newOrder._id });
    } catch (err) {
        console.error('Checkout error:', err);
        res.status(500).json({ success: false, message: 'Failed to place order.' });
    }
});

// --- PROTECTED ROUTES: ADMIN ACTIONS ---

// Add product
app.post('/api/products', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin only.' });

    try {
        const newProduct = new Product(req.body);
        await newProduct.save();
        res.status(201).json({ message: 'Product added successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to add product' });
    }
});

// Delete product
app.delete('/api/products/:name', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin only.' });

    try {
        const result = await Product.deleteOne({ name: req.params.name });
        if (result.deletedCount === 0) return res.status(404).json({ error: 'Product not found' });
        res.json({ message: 'Product deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete product' });
    }
});

// Update product
app.put('/api/products/:name', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin only.' });

    try {
        const product = await Product.findOneAndUpdate({ name: req.params.name }, req.body, { new: true });
        if (!product) return res.status(404).json({ error: 'Product not found' });
        res.json({ message: 'Product updated successfully', product });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update product' });
    }
});

// Get all users
app.get('/api/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin only.' });

    try {
        const users = await User.find().select('-password'); // hide password
        res.json(users);
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// Delete user
app.delete('/api/users/:email', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin only.' });

    try {
        const result = await User.deleteOne({ email: req.params.email });
        if (result.deletedCount === 0) return res.status(404).json({ success: false, message: 'User not found.' });
        res.json({ success: true, message: 'User deleted successfully.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to delete user.' });
    }
});

// Get all orders
app.get('/api/orders', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin only.' });

    try {
        const orders = await Order.find();
        res.json(orders);
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// Logout
app.post('/api/logout', (req, res) => {
    res.json({ success: true, message: 'Logged out successfully.' });
});

// --- START THE SERVER ---
app.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
});
