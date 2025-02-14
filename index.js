const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(express.static("public"));

app.use(cors({ origin: "http://127.0.0.1:5500" }));
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});
db.connect((err) => {
    if (err) {
        console.error("Database connection failed: ", err);
    } else {
        console.log("Connected to MySQL");
    }
});

app.post("/register", async (req, res) => {
    const { name, email, password } = req.body;

    try {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        db.query("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", 
        [name, email, hashedPassword], (err, result) => {
            if (err) {
                console.error("Error inserting user:", err);
                return res.status(500).json({ error: "Error registering user" });
            }
            res.status(201).json({ message: "User registered successfully" });
        });
    } catch (error) {
        console.error("Error hashing password:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post("/login", async(req, res) =>{
    const {email, password} = req.body
    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) =>{
        if(err){
            console.error("Database query error: ", err)
            return res.status(500).json({error: "Internal Server Error"})
        }
        if(results.length == 0 ){
            return res.status(401).json({error: "Invalid email or password"})
        }
        const user = results[0]
        const passwordMatch = await bcrypt.compare(password, user.password)

        if(!passwordMatch){
            return res.status(401).json({error: "Invalid email or password" })
        }
        res.json({ message: "Login successful", user: { id: user.id, email: user.email } });
    })
})

app.listen(3000, () => {
    console.log("Server running on port 3000");
});
