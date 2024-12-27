require('dotenv').config({ path: '../.env' });

const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const AppleStrategy = require('passport-apple').Strategy;
const path = require('path');

const app = express();
const port = 3000;

// Middleware and setup
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use(passport.initialize());

// MySQL connection using .env credentials
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET;

// Serve static files from the frontend folder
app.use(express.static(path.join(__dirname, '../frontend')));

// Serve registration.html as the default page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/registration.html'));
});

// Social login configuration
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        // Check if user exists, or create new user
        db.query('CALL sp_GetUser(?)', [profile.id], async (err, results) => {
            if (err) return done(err);

            const user = results[0][0];
            if (!user) {
                db.query('CALL sp_CreateSocialUser(?, ?, ?)', [profile.id, profile.displayName, profile.emails[0].value], (err, result) => {
                    if (err) return done(err);
                    done(null, result[0]);
                });
            } else {
                done(null, user);
            }
        });
    } catch (error) {
        done(error, null);
    }
}));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        db.query('CALL sp_GetUser(?)', [profile.id], async (err, results) => {
            if (err) return done(err);

            const user = results[0][0];
            if (!user) {
                db.query('CALL sp_CreateSocialUser(?, ?, ?)', [profile.id, profile.displayName, profile.emails[0].value], (err, result) => {
                    if (err) return done(err);
                    done(null, result[0]);
                });
            } else {
                done(null, user);
            }
        });
    } catch (error) {
        done(error, null);
    }
}));

passport.use(new AppleStrategy({
    clientID: process.env.APPLE_CLIENT_ID,
    teamID: process.env.APPLE_TEAM_ID,
    privateKey: process.env.APPLE_PRIVATE_KEY,
    callbackURL: "http://localhost:3000/auth/apple/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        db.query('CALL sp_GetUser(?)', [profile.id], async (err, results) => {
            if (err) return done(err);

            const user = results[0][0];
            if (!user) {
                db.query('CALL sp_CreateSocialUser(?, ?, ?)', [profile.id, profile.displayName, profile.email], (err, result) => {
                    if (err) return done(err);
                    done(null, result[0]);
                });
            } else {
                done(null, user);
            }
        });
    } catch (error) {
        done(error, null);
    }
}));

// Routes

// Google Auth
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Facebook Auth
app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));

// Apple Auth
app.get('/auth/apple', passport.authenticate('apple'));

// Google callback
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
    const token = jwt.sign({ id: req.user.id, mobile: req.user.mobile }, JWT_SECRET, { expiresIn: '1h' });
    res.redirect(`/welcome?token=${token}`);
});

// Facebook callback
app.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/login' }), (req, res) => {
    const token = jwt.sign({ id: req.user.id, mobile: req.user.mobile }, JWT_SECRET, { expiresIn: '1h' });
    res.redirect(`/welcome?token=${token}`);
});

// Apple callback
app.get('/auth/apple/callback', passport.authenticate('apple', { failureRedirect: '/login' }), (req, res) => {
    const token = jwt.sign({ id: req.user.id, mobile: req.user.mobile }, JWT_SECRET, { expiresIn: '1h' });
    res.redirect(`/welcome?token=${token}`);
});

// Registration API
app.post('/api/register', async (req, res) => {
    const { firstName, lastName, mobile, password } = req.body;
    const createdDate = new Date();
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.query('CALL sp_CreateUser(?, ?, ?, ?)', [firstName, lastName, mobile, hashedPassword], (err, result) => {
            if (err) {
                console.error('Registration error:', err);
                return res.status(500).json({ success: false, message: 'Registration failed' });
            }
            res.json({ success: true, message: 'Registration successful' });
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error during registration' });
    }
});

// Login API
app.post('/api/login', async (req, res) => {
    const { mobile, password } = req.body;

    try {
        // Query user based on the provided mobile
        db.query('CALL sp_GetUser(?)', [mobile], async (err, results) => {
            if (err) {
                console.error('Database query error:', err); // Log the error
                return res.status(500).json({ success: false, message: 'Database query error' });
            }

            // Check if user exists
            const user = results[0][0];
            if (!user) {
                return res.status(401).json({ success: false, message: 'Invalid credentials' });
            }

            // Compare password
            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(401).json({ success: false, message: 'Invalid credentials' });
            }

            // Generate JWT token
            const token = jwt.sign({ id: user.id, mobile: user.mobile }, JWT_SECRET, { expiresIn: '1h' });

            // Respond with success
            res.json({
                success: true,
                token,
                message: 'Login successful',
                user: {
                    firstName: user.first_name,
                    lastName: user.last_name
                }
            });
        });
    } catch (error) {
        console.error('Error during login process:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});


function verifyToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(403).json({ success: false, message: 'No token provided' });
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ success: false, message: 'Invalid token' });
        req.user = decoded;
        next();
    });
}

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
