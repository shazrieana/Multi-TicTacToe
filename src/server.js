const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const http = require("http");
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

const templatePath = path.join(__dirname, "../templates/views");
app.set("views", templatePath);
app.set("view engine", "ejs");

app.use(express.static(path.resolve(""))); // Serve static files
app.use(bodyParser.urlencoded({ extended: true })); // Parse URL-encoded bodies
app.use(express.json()); // Parse JSON bodies
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true
}));




// User signup route
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = new User({ username, password });
        await user.save();
        req.session.userId = user._id;
        res.redirect('/game');
    } catch (error) {
        res.status(400).send('Error signing up');
    }
});

// User login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user || user.password !== password) {
            return res.status(400).send('Invalid credentials');
        }
        req.session.userId = user._id;
        res.redirect('/game');
    } catch (error) {
        res.status(400).send('Error logging in');
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
    res.sendFile(path.resolve('game.html'));
});

// Serve index page
app.get('/', (req, res) => {
    res.sendFile(path.resolve('index.html'));
});

// Serve signup page
app.get('/signup', (req, res) => {
    res.render('signup');
});

// Serve login page
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

let arr = [];
let playingArray = [];

// Socket.IO connection
io.on("connection", (socket) => {
    socket.on("find", (e) => {
        if (e.name != null) {
            arr.push(e.name);
            if (arr.length >= 2) {
                let p1obj = {
                    p1name: arr[0],
                    p1value: "X",
                    p1move: ""
                };
                let p2obj = {
                    p2name: arr[1],
                    p2value: "O",
                    p2move: ""
                };
                let gameObj = {
                    p1: p1obj,
                    p2: p2obj,
                    sum: 0,
                    allPlayers: arr
                };
                playingArray.push(gameObj);
                io.emit("playing", gameObj);
                arr = []; // Reset the array for the next game
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
            game.sum += data.moveValue;
            io.emit("playing", game);
        }
    });

    socket.on("gameOver", (e) => {
        playingArray = playingArray.filter(obj => obj.p1.p1name !== e.name);
        console.log(playingArray);
        console.log("Game Over");
    });
});

server.listen(3000, () => {
    console.log("Server is running on port 3000");
});

module.exports = { server, io, app };