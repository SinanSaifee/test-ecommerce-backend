// --- LOAD ENVIRONMENT VARIABLES ---
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3001;

// --- FILE PATHS FOR DATA STORAGE ---
const DATA_FILE = path.join(__dirname, 'products.json');
const USERS_FILE = path.join(__dirname, 'users.json');
const ORDERS_FILE = path.join(__dirname, 'orders.json');

// --- SECRET KEY AND JWT EXPIRATION ---
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key_here';
const JWT_EXPIRATION_TIME = '15d';
const saltRounds = 10;

// --- ADMIN CREDENTIALS FROM .ENV ---
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'adminpass';

// --- MIDDLEWARE SETUP ---
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// --- AUTHENTICATION MIDDLEWARE ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.status(401).json({ message: 'Authentication token required.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification error:', err.message);
            return res.status(403).json({ message: 'Invalid or expired token.' });
        }
        req.user = user;
        next();
    });
}

// --- HELPER FUNCTION TO READ FILES ---
function readFile(filePath, callback) {
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            if (err.code === 'ENOENT') {
                return callback([]);
            }
            console.error(`Failed to read file ${filePath}:`, err);
            return callback(null, err);
        }
        try {
            const parsedData = JSON.parse(data);
            callback(parsedData);
        } catch (parseErr) {
            console.error(`Failed to parse JSON from ${filePath}:`, parseErr);
            callback(null, parseErr);
        }
    });
}

// --- HELPER FUNCTION TO WRITE FILES ---
function writeFile(filePath, data, callback) {
    fs.writeFile(filePath, JSON.stringify(data, null, 2), callback);
}

// =========================================================================
//                             API ENDPOINTS
// =========================================================================

// --- PUBLIC ROUTES: AUTHENTICATION AND PRODUCTS ---

// Route for user registration
app.post('/api/register', (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    readFile(USERS_FILE, users => {
        if (!users) return res.status(500).json({ success: false, message: 'Server error.' });
        const existingUser = users.find(u => u.email === email);
        if (existingUser) {
            return res.status(409).json({ success: false, message: 'Email already registered.' });
        }

        bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
            if (err) {
                console.error("Password hashing failed:", err);
                return res.status(500).json({ success: false, message: 'Registration failed.' });
            }

            const newUser = {
                name,
                email,
                password: hashedPassword,
                createdAt: new Date().toISOString(),
                role: 'user'
            };

            users.push(newUser);
            writeFile(USERS_FILE, users, (err) => {
                if (err) {
                    return res.status(500).json({ success: false, message: 'Failed to save user data.' });
                }
                res.status(201).json({ success: true, message: 'Registration successful!' });
            });
        });
    });
});

// Route for user login (including admin login)
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    if (email === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        const user = { email: ADMIN_USERNAME, role: 'admin', name: 'Admin' };
        const accessToken = jwt.sign(user, JWT_SECRET, { expiresIn: JWT_EXPIRATION_TIME });
        return res.json({ success: true, token: accessToken, expires_in: JWT_EXPIRATION_TIME, user });
    }

    readFile(USERS_FILE, users => {
        if (!users) return res.status(500).json({ success: false, message: 'Server error.' });
        const user = users.find(u => u.email === email);
        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        bcrypt.compare(password, user.password, (err, result) => {
            if (err || !result) {
                return res.status(401).json({ success: false, message: 'Invalid credentials' });
            }

            const payload = {
                email: user.email,
                name: user.name,
                role: user.role || 'user'
            };
            const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRATION_TIME });
            res.json({ success: true, token: accessToken, expires_in: JWT_EXPIRATION_TIME, user: payload });
        });
    });
});

// Route for getting a list of products (publicly accessible)
app.get('/api/products', (req, res) => {
    readFile(DATA_FILE, products => {
        if (!products) return res.status(500).json({ error: 'Server error' });

        const { category, minPrice, maxPrice, name } = req.query;
        let filteredProducts = products;

        if (category) filteredProducts = filteredProducts.filter(p => p.category === category);
        if (minPrice) filteredProducts = filteredProducts.filter(p => p.price >= parseFloat(minPrice));
        if (maxPrice) filteredProducts = filteredProducts.filter(p => p.price <= parseFloat(maxPrice));
        if (name) {
            const searchNameLower = name.toLowerCase();
            filteredProducts = filteredProducts.filter(p => p.name.toLowerCase().includes(searchNameLower));
        }
        res.json(filteredProducts);
    });
});

// Route for user checkout (now handles both authenticated and guest users)
app.post('/api/checkout', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    let user = { name: 'Guest', email: 'guest@example.com' }; // Default guest user

    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            user = { name: decoded.name, email: decoded.email };
        } catch (err) {
            // Invalid token, continue as guest
            console.error('Invalid token for checkout, proceeding as guest:', err.message);
        }
    }

    const { cartItems, shippingInfo, paymentInfo } = req.body;

    if (!cartItems || !Array.isArray(cartItems) || cartItems.length === 0) {
        return res.status(400).json({ success: false, message: 'Cart cannot be empty.' });
    }
    if (!shippingInfo || Object.keys(shippingInfo).length === 0) {
        return res.status(400).json({ success: false, message: 'Shipping information is required.' });
    }

    const order = {
        orderId: Date.now(),
        user: {
            email: user.email,
            name: user.name,
        },
        items: cartItems,
        shipping: shippingInfo,
        payment: { method: paymentInfo?.method || 'Not Specified', status: 'Completed' },
        createdAt: new Date().toISOString()
    };

    readFile(ORDERS_FILE, orders => {
        if (!orders) orders = [];
        orders.push(order);
        writeFile(ORDERS_FILE, orders, (err) => {
            if (err) {
                console.error("Failed to save order:", err);
                return res.status(500).json({ success: false, message: 'Failed to place order.' });
            }
            console.log('New Order Received and Saved:', order.orderId);
            res.json({ success: true, message: 'Checkout successful! Your order has been placed.' });
        });
    });
});

// --- PROTECTED ROUTES: ADMIN ACTIONS ---
// (These routes remain unchanged and require a valid admin token)

app.post('/api/products', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied. Admin only.' });
    }
    const newProduct = req.body;
    if (!newProduct.name || !newProduct.price || !newProduct.category) {
        return res.status(400).json({ success: false, message: 'Product name, price, and category are required.' });
    }

    readFile(DATA_FILE, products => {
        if (!products) return res.status(500).json({ error: 'Server error' });
        const existingProduct = products.find(p => p.name === newProduct.name);
        if (existingProduct) {
            return res.status(409).json({ success: false, message: 'A product with this name already exists.' });
        }
        products.unshift(newProduct);
        writeFile(DATA_FILE, products, (err) => {
            if (err) return res.status(500).json({ error: 'Failed to write file' });
            res.status(201).json({ message: 'Product added successfully' });
        });
    });
});

app.delete('/api/products/:name', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied. Admin only.' });
    }
    const nameToDelete = req.params.name;
    readFile(DATA_FILE, products => {
        if (!products) return res.status(500).json({ error: 'Server error' });
        const filtered = products.filter(p => p.name !== nameToDelete);
        if (filtered.length === products.length) {
            return res.status(404).json({ error: 'Product not found' });
        }
        writeFile(DATA_FILE, filtered, (err) => {
            if (err) return res.status(500).json({ error: 'Failed to write file' });
            res.json({ message: 'Product deleted successfully' });
        });
    });
});

app.put('/api/products/:name', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied. Admin only.' });
    }
    const nameToUpdate = req.params.name;
    const updatedProduct = req.body;

    readFile(DATA_FILE, products => {
        if (!products) return res.status(500).json({ error: 'Server error' });
        const productIndex = products.findIndex(p => p.name === nameToUpdate);
        if (productIndex === -1) {
            return res.status(404).json({ error: 'Product not found' });
        }
        products[productIndex] = { ...products[productIndex], ...updatedProduct };
        writeFile(DATA_FILE, products, (err) => {
            if (err) return res.status(500).json({ error: 'Failed to write file' });
            res.json({ message: 'Product updated successfully' });
        });
    });
});

app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied. Admin only.' });
    }
    readFile(USERS_FILE, users => {
        if (!users) return res.status(500).json({ success: false, message: 'Server error.' });
        const safeUsers = users.map(({ password, ...user }) => user);
        res.json(safeUsers);
    });
});

app.delete('/api/users/:email', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied. Admin only.' });
    }
    const emailToDelete = req.params.email;
    readFile(USERS_FILE, users => {
        if (!users) return res.status(500).json({ success: false, message: 'Server error.' });
        const initialLength = users.length;
        const filteredUsers = users.filter(user => user.email !== emailToDelete);

        if (initialLength === filteredUsers.length) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        writeFile(USERS_FILE, filteredUsers, (err) => {
            if (err) {
                console.error("Failed to delete user:", err);
                return res.status(500).json({ success: false, message: 'Failed to delete user.' });
            }
            res.json({ success: true, message: 'User deleted successfully.' });
        });
    });
});

app.get('/api/orders', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied. Admin only.' });
    }
    readFile(ORDERS_FILE, orders => {
        if (!orders) return res.status(500).json({ success: false, message: 'Server error.' });
        res.json(orders);
    });
});

app.post('/api/logout', (req, res) => {
    res.json({ success: true, message: 'Logged out successfully.' });
});

// --- START THE SERVER ---
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});