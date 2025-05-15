require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();

// Middleware
app.use(cors({
  origin: "https://auth-front-865y.onrender.com/", // Removed trailing slash
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Added OPTIONS
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization"],
}));
app.use(bodyParser.json());

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/auth_demo')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User model
const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
}));

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';



// Routes
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to the Auth API',
    endpoints: {
      register: 'POST /api/register',
      login: 'POST /api/login',
      profile: {
        get: 'GET /api/profile/:id',
        update: 'PUT /api/profile/:id',
        delete: 'DELETE /api/profile/:id'
      }
    }
  });
});

// Register a new user
app.post('/api/register', async (req, res) => {
  try {
    console.log('Registration request:', req.body);
    const { username, email, password } = req.body;
    
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      console.log('Duplicate user attempt:', { username, email });
      return res.status(400).json({ message: 'Username or email already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();
    
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });
    console.log('User registered successfully:', username);
    
    res.status(201).json({ token, userId: user._id, username: user.username });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      message: 'Error registering user',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// [Keep other routes (login, profile, etc.) with similar error handling improvements]

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));