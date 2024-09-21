const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

app.use(bodyParser.json());

const secretKey = 'your-secret-key';
let users = []; // In-memory user storage (use a DB in production)

// Middleware to verify JWT
function verifyToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).send('A token is required');

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) return res.status(401).send('Invalid token');
        req.user = decoded; 
        next();
    });
}

// POST: Register a new user
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Username and password are required');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    users.push({ username, password: hashedPassword });
    res.status(201).send('User registered successfully');
});

// POST: Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);
    if (!user) return res.status(400).send('Invalid username or password');

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).send('Invalid username or password');

    const token = jwt.sign({ username }, secretKey, { expiresIn: '1h' });
    res.status(200).send({ token });
});

// GET: Protected route
app.get('/protected', verifyToken, (req, res) => {
    res.status(200).send(`Hello, ${req.user.username}`);
});

// POST: Create a resource (protected)
app.post('/resource', verifyToken, (req, res) => {
    res.status(201).send('Resource created');
});

// PUT: Update a resource (protected)
app.put('/resource/:id', verifyToken, (req, res) => {
    const { id } = req.params;
    res.status(200).send(`Resource with id ${id} updated`);
});

// DELETE: Delete a resource (protected)
app.delete('/resource/:id', verifyToken, (req, res) => {
    const { id } = req.params;
    res.status(200).send(`Resource with id ${id} deleted`);
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
