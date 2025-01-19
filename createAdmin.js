// filepath: /c:/Users/User/Desktop/Multi TicTacToe/createAdmin.js
require('dotenv').config();
const mongoose = require('mongoose');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./src/models/User'); // Ensure this path is correct

const uri = "mongodb+srv://shaz:Shazhebat2002@cluster0.dnahz.mongodb.net/tic-tac-toe?retryWrites=true&w=majority&appName=Cluster0";

mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Connected to MongoDB Atlas"))
    .catch(err => console.error("Could not connect to MongoDB Atlas", err));

async function createAdmin() {
    const username = 'admin';
    const password = 'adminpassword';
    const role = 'admin';

    const hashedPassword = await bcryptjs.hash(password, 10);
    const token = jwt.sign({ username: username, role: role }, process.env.JWT_SECRET, { expiresIn: '10m' });

    const adminUser = new User({
        username: username,
        password: hashedPassword,
        token: token,
        role: role
    });

    await adminUser.save();
    console.log('Admin user created:', adminUser);
    mongoose.disconnect();
}

createAdmin().catch(err => console.error(err));