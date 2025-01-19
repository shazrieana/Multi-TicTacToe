// filepath: /c:/Users/User/Desktop/Multi TicTacToe/models/User.js
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    token: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' }
});

//const Collection = new mongoose.model("AuthCollection", UserSchema);
const User = mongoose.model('User', UserSchema);
module.exports = User;