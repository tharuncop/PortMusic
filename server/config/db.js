const mongoose = require('mongoose');

const connectDB = async() => {
    try{
        await mongoose.connect(process.env.MOGO_URI);
        console.log("MongoDB Connected Successfully");
    }
    catch(error){
        console.log("Database Connection Error: ", error.message);
    }
}

module.exports = connectDB;