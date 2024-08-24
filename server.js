require('dotenv').config();
const mongoose = require('mongoose');
const express = require('express');
const app = express();

const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('MongoDB connected');
    } catch (err) {
        console.error('Error connecting to MongoDB:', err.message);
        process.exit(1); // Exit process with failure
    }
};

connectDB();
app.use(express.json());
const PORT = process.env.PORT || 5000;
app.use('/api', require('./routes/auth'));

const authRoutes = require('./routes/auth');
app.use('/api/auth', authRoutes);

app.listen(5000, () => console.log('Server started on port 5000'));
