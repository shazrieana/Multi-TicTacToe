require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const http = require("http");
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcryptjs = require('bcryptjs');
const { Server } = require("socket.io");
const bodyParser = require('body-parser');
const session = require('express-session');
const User = require('./models/User'); // Ensure this path is correct

const app = express();

const uri = "mongodb+srv://shaz:Shazhebat2002@cluster0.dnahz.mongodb.net/tic-tac-toe?retryWrites=true&w=majority&appName=Cluster0";

mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Connected to MongoDB Atlas"))
    .catch(err => console.error("Could not connect to MongoDB Atlas", err));

const server = http.createServer(app);
const io = new Server(server);

const publicPath = path.join(__dirname, "../public");
const templatePath = path.join(__dirname, "../templates/views");

app.set("views", templatePath);
app.set("view engine", "ejs");

app.use(express.static(publicPath));
app.use(express.static(path.resolve(""))); // Serve static files
app.use(express.urlencoded({ extended: false })); // Parse URL-encoded bodies
app.use(bodyParser.urlencoded({ extended: true })); // Parse URL-encoded bodies
app.use(express.json()); // Parse JSON bodies
app.use(cookieParser());


async function hashPass(password) {
    const res = await bcryptjs.hash(password, 10);
    return res;
}

async function compare(userPass,hashPass) {
    const res = await bcryptjs.compare(userPass,hashPass);
    return res;
}

// Password validation function
function validatePassword(password) {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    return passwordRegex.test(password);
}

app.use(session({
    secret: 'namasayanurulshazrieanabintimadsaidsayaberumur23tahun',
    resave: false,
    saveUninitialized: true
}));

// Middleware to check if the user is an admin
function isAdmin(req, res, next) {
    if (req.cookies.jwt) {
        try {
            const verify = jwt.verify(req.cookies.jwt, process.env.JWT_SECRET);
            if (verify.role === 'admin') {
                req.user = verify;
                return next();
            }
        } catch (error) {
            res.clearCookie("jwt");
        }
    }
    return res.status(403).send('Access denied');
}

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Protected endpoint
app.get('/protected-route', authenticateToken, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
});

// User signup route
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    const role = 'user'; //Default role is user
    try {
        if (!validatePassword(password)) {
            return res.status(400).json({message: 'Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.'});
        }

        const check = await User.findOne({ username:req.body.username });
        if (check) {
            //alert('Username already exists');
            return res.status(400).json({ message: 'Username already exists' });
        }
        else {
   
        const token = jwt.sign({ username: req.body.username, role: role }, process.env.JWT_SECRET, { expiresIn: '10m' });

        res.cookie("jwt", token, {
            maxAge: 600000, // token dia tahan 10 minutes
            httpOnly: true //  takleh diakses melalui javascript
            
        })

        const data = {
            username: req.body.username,
            password: await hashPass(req.body.password),
            token: token,
            role: role
        }

        await User.insertMany(data);

        console.log('User created: ', data);
            res.status(200).json({ message: 'User created successfully', redirect: '/login' });
        }
    } catch (error) {
        console.error('Error signing up:', error);
        res.status(400).json({ message: 'Error signing up' });
    }
});

// User login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const check = await User.findOne({ username: req.body.username });
        if (!check) {
            return res.status(400).json({ message: 'Wrong username or password' });
        }

        const passchek = await compare(req.body.password, check.password);
        if (!passchek) {
            return res.status(400).json({ message: 'Wrong username or password' });
        }

        const token = jwt.sign({ username: req.body.username, role: check.role }, process.env.JWT_SECRET, { expiresIn: '10m' });

        res.cookie("jwt", token, {
            maxAge: 600000, // cookie lasts 10 minutes
            httpOnly: true // cookie cannot be accessed via JavaScript
        });

        if (check.role === 'admin') {
            res.status(200).json({ message: 'Login successful', redirect: '/admin' });
        } else {
            res.status(200).json({ message: 'Login successful', redirect: '/game' });
        }
    } catch (error) {
        res.status(400).json({ message: 'Error logging in' });
    }
});


// User logout route
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Serve game page
app.get('/game', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/');
    }
    res.render('game', { username: req.session.username });
});

// Serve index page
app.get('/', (req, res) => {
    if(req.cookies.jwt) {
        try {
        //const verify = jwt.verify(req.cookies.jwt, "namasayanurulshazrieanabintimadsaidsayaberumur23tahun");
        const verify = jwt.verify(req.cookies.jwt, process.env.JWT_SECRET || "namasayanurulshazrieanabintimadsaidsayaberumur23tahun");
        if (verify.role === 'admin') {
            res.render('admin', { username: verify.username });
        } else {
        res.render("game", {username: verify.username});
    }
    } catch (error) {
        res.clearCookie('jwt');
        res.render('login');
    }
    }else{
        res.render('login');
    }
    //res.sendFile(path.resolve('index.html'));
});

// Serve signup page
app.get('/signup', (req, res) => {
    res.render('signup');
});

//Serve login page
app.get('/login', (req, res) => {
    res.render('login');
});

// Get all users (example route)
app.get("/getUsers", async (req, res) => {
    try {
        const users = await User.find({});
        res.json(users);
    } catch (err) {
        res.status(500).json(err);
    }
});

// Get all users (example route)
app.get("/api/users", isAdmin, async (req, res) => {
    try {
        const users = await User.find({});
        res.json(users);
    } catch (err) {
        res.status(500).json(err);
    }
});

// Create a new user (admin only)
app.post("/api/users", isAdmin, async (req, res) => {
    const { username, password, role } = req.body;
    try {
        const hashedPassword = await hashPass(password);
        const newUser = new User({ username, password: hashedPassword, role });
        await newUser.save();
        res.status(201).json(newUser);
    } catch (err) {
        res.status(400).json(err);
    }
});

// Update a user (admin only)
app.put("/api/users/:id", isAdmin, async (req, res) => {
    const { username, password, role } = req.body;
    try {
        const hashedPassword = password ? await hashPass(password) : undefined;
        const updatedUser = await User.findByIdAndUpdate(req.params.id, {
            username,
            ...(hashedPassword && { password: hashedPassword }),
            role
        }, { new: true });
        res.json(updatedUser);
    } catch (err) {
        res.status(400).json(err);
    }
});

// Delete a user (admin only)
app.delete("/api/users/:id", isAdmin, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.status(204).send();
    } catch (err) {
        res.status(400).json(err);
    }
});

let waitingPlayer = null;
let playingArray = [];

// Socket.IO connection
io.on("connection", (socket) => {
    socket.on("find", (e) => {
        if (e.name != null) {
            if (waitingPlayer == null) {
                waitingPlayer = { name: e.name, socket: socket };
                socket.emit("waiting", { message: "Waiting for another player..." });
            } else {
                let p1obj = {
                    p1name: waitingPlayer.name,
                    p1value: "X",
                    p1move: ""
                };
                let p2obj = {
                    p2name: e.name,
                    p2value: "O",
                    p2move: ""
                };
                let gameObj = {
                    p1: p1obj,
                    p2: p2obj,
                    sum: 0,
                    allPlayers: [waitingPlayer.name, e.name]
                };
                playingArray.push(gameObj);
                waitingPlayer.socket.emit("playing", gameObj);
                socket.emit("playing", gameObj);
                waitingPlayer = null; // Reset the waiting player
            }
        }
    });

    socket.on("move", (data) => {
        let game = playingArray.find(game => game.p1.p1name === data.name || game.p2.p2name === data.name);
        if (game) {
            if (game.p1.p1name === data.name) {
                game.p1.p1move = data.move;
            } else {
                game.p2.p2move = data.move;
            }
            game.sum += 1;
            io.emit("playing", game);
        }
    });

    socket.on("gameOver", (data) => {
        playingArray = playingArray.filter(obj => obj.p1.p1name !== data.name && obj.p2.p2name !== data.name);
        console.log(playingArray);
        console.log("Game Over");
        io.emit("gameOver", data);
    });
});

server.listen(3000, () => {
    console.log("Server is running on port 3000");
});

module.exports = { server, io, app };