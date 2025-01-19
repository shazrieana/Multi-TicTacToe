// filepath: /c:/Users/User/Desktop/Multi TicTacToe/models/User.js
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    token: { type: String, required: true },
});

//const Collection = new mongoose.model("AuthCollection", UserSchema);

module.exports = mongoose.model('User', UserSchema);