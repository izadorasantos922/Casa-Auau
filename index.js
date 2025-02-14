const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const cors = require("cors");
require("dotenv").config();
const jwt = require("jsonwebtoken")

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
        db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
            if (err) {
                console.error("Database query error:", err);
                return res.status(500).json({ error: "Internal Server Error" });
            }

            if (results.length > 0) {
                return res.status(400).json({ error: "Email is already registered" });
            }

            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            db.query("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", 
            [name, email, hashedPassword], (err, result) => {
                if (err) {
                    console.error("Error inserting user:", err);
                    return res.status(500).json({ error: "Error registering user" });
                }

                const user = { id: result.insertId, email };

                try {
                    const token = jwt.sign(
                        { userId: user.id, email: user.email },
                        process.env.JWT_SECRET,
                        { expiresIn: '1h' }
                    );
                    res.status(201).json({ message: "User registered successfully", token });
                } catch (jwtError) {
                    console.error("Error generating JWT:", jwtError);
                    res.status(500).json({ error: "Error generating token" });
                }
            });
        });
    } catch (error) {
        console.error("Error hashing password:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});


app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
            if (err) {
                console.error("Database query error:", err);
                return res.status(500).json({ error: "Internal Server Error" });
            }

            if (results.length === 0) {
                return res.status(400).json({ error: "Invalid email or password" });
            }

            const user = results[0];
            const isPasswordValid = await bcrypt.compare(password, user.password);

            if (!isPasswordValid) {
                return res.status(400).json({ error: "Invalid email or password" });
            }

            const token = jwt.sign(
                { userId: user.id, email: user.email },
                process.env.JWT_SECRET,{ expiresIn: '1h' }
            );
            res.status(200).json({ message: "Login successful", token });
        });
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});
