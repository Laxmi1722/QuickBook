const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
require('dotenv').config();
const User = require('./models/User.js');
const Booking = require('./models/Booking.js');
const { image } = require('image-downloader');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');
const Place = require('./models/Place.js');

const bcryptSalt = bcrypt.genSaltSync(10);
const jwtSecret = 'fasefraw4r5r3wq45wdfgw34twdfg';

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(path.join(__dirname, '/uploads')));
app.use(cors({
    credentials: true,
    origin: "http://localhost:5173",
}));

mongoose.connect(process.env.MONGO_URL, {
  useNewUrlParser: true,
  ssl: true,
  tlsInsecure: true,
}).then(() => {
    console.log('Connected to MongoDB');
}).catch(err => {
    console.error('Error connecting to MongoDB:', err);
});

async function getUserDataFromToken(req) {
    return new Promise((resolve, reject) => {
        const { token } = req.cookies;
        if (!token) {
            return reject('No token provided');
        }
        jwt.verify(token, jwtSecret, {}, (err, userData) => {
            if (err) return reject(err);
            resolve(userData);
        });
    });
}

app.get('/test', (req, res) => {
    res.json('Hello World');
});

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        const hashedPassword = bcrypt.hashSync(password, bcryptSalt);
        const userDoc = await User.create({ name, email, password: hashedPassword });
        res.status(201).json(userDoc);
    } catch (error) {
        if (error.code === 11000) {
            res.status(400).json({ error: 'Email already exists' });
        } else {
            res.status(500).json({ error: 'Internal Server Error' });
        }
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const userDoc = await User.findOne({ email });
        if (!userDoc) {
            return res.status(404).json({ error: 'User not found' });
        }

        const passOk = bcrypt.compareSync(password, userDoc.password);
        if (!passOk) {
            return res.status(422).json({ error: 'Password not correct' });
        }

        jwt.sign({ email: userDoc.email, id: userDoc._id }, jwtSecret, {}, (err, token) => {
            if (err) {
                console.error('JWT signing error:', err);
                return res.status(500).json({ error: 'Internal Server Error' });
            }
            res.cookie('token', token).json(userDoc);
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/profile', async (req, res) => {
    try {
        const userData = await getUserDataFromToken(req);
        const user = await User.findById(userData.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        const { name, email, _id } = user;
        res.json({ name, email, _id });
    } catch (err) {
        console.error('Profile retrieval error:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/logout', (req, res) => {
    res.cookie('token', '').json(true);
});

app.post('/upload-by-link', async (req, res) => {
    const { link } = req.body;
    const newName = Date.now() + '.jpg';
    const destPath = path.join(__dirname, 'uploads', newName);

    try {
        await image({
            url: link,
            dest: destPath,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        });
        res.json(newName);
    } catch (error) {
        console.error('Image download error:', error);
        res.status(500).json({ error: 'Failed to download image' });
    }
});

const photosMiddleware = multer({ dest: '/tmp' });
app.post('/api/upload', photosMiddleware.array('photos', 100), async (req, res) => {
    const uploadedFiles = [];
    for (let i = 0; i < req.files.length; i++) {
        const { path, originalname } = req.files[i];
        const parts = originalname.split('.');
        const ext = parts[parts.length - 1];
        const newPath = path + '.' + ext;
        fs.renameSync(path, newPath);
        uploadedFiles.push(newPath.replace('/uploads', ''));
    }
    res.json(uploadedFiles);
});

app.post('/places', async (req, res) => {
    try {
        const userData = await getUserDataFromToken(req);
        const { title, address, addedPhotos, description, perks, extraInfo, checkIn, checkOut, maxGuests } = req.body;
        const placeDoc = await Place.create({
            owner: userData.id,
            title,
            address,
            photos: addedPhotos,
            description,
            perks,
            extraInfo,
            checkIn,
            checkOut,
            maxGuests
        });
        res.json(placeDoc);
    } catch (err) {
        console.error('Error creating place:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/places', async (req, res) => {
    try {
        const userData = await getUserDataFromToken(req);
        const places = await Place.find({ owner: userData.id });
        res.json(places);
    } catch (err) {
        console.error('Error retrieving places:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/places/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const place = await Place.findById(id);
        res.json(place);
    } catch (err) {
        console.error('Error retrieving place by ID:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.put('/places', async (req, res) => {
    const { id, title, address, addedPhotos, description, perks, extraInfo, checkIn, checkOut, maxGuests, price } = req.body;
    try {
        const userData = await getUserDataFromToken(req);
        const placeDoc = await Place.findById(id);
        if (userData.id === placeDoc.owner.toString()) {
            placeDoc.set({
                title, address, photos: addedPhotos, description, perks, extraInfo, checkIn, checkOut, maxGuests, price
            });
            await placeDoc.save();
            res.json('ok');
        } else {
            res.status(403).json({ error: 'Unauthorized' });
        }
    } catch (err) {
        console.error('Error updating place:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/all-places', async (req, res) => { // Renamed to avoid conflict
    try {
        const places = await Place.find();
        res.json(places);
    } catch (err) {
        console.error('Error retrieving all places:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/bookings', async (req, res) => {
    try {
        const userData = await getUserDataFromToken(req);
        const { place, checkIn, checkOut, numberOfGuests, name, phone, price } = req.body;
        const booking = await Booking.create({
            place, checkIn, checkOut, numberOfGuests, name, phone, price,
            user: userData.id,
        });
        res.json('OK');
    } catch (err) {
        console.error('Error creating booking:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.listen(4000, () => {
    console.log('Server is running on port 4000');
});
