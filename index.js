const express = require("express");
const bcrypt = require("bcrypt");


const app = express();
app.use(express.json());
const port = process.env.PORT || "8112";

// in memory storage for now
const users = {};

app.post("/api/v1/users/register", (req,res)  => {
    const username = req.body.username || "";
    const password = req.body.password || "";

    res.setHeader("Content-Type", "application/json");
    
    if(!username || !password || users[username]) {
        res.status(400).send("Invalid user name or password.");
    }

    bcrypt.hash(password, 10, (err, hash) => {
        if(hash) {
            users[username] = {hash};
            res.sendStatus(200);
        }
        else {
            res.sendStatus(500);
        }
        
    });
});

app.post("/api/v1/users/auth", (req,res) => {
    const username = req.body.username || "";
    const password = req.body.password || "";

    if(!username || !password || !users[username]) {
        res.sendStatus(400);
    }

    const { hash } = users[username];

    bcrypt.compare(password, hash, (err, response) => {
        // successfully compared password with hash
        if(response) {
            res.sendStatus(200);
        }
        else {
            res.sendStatus(401);
        }
    });
});

app.listen(port, () => {
    console.log(`Server started on port: ${port}`);
});