const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());
const port = process.env.PORT || "8112";

// in memory storage for now
const users = {};

app.get("/", (req,res) => {
    res.send("Hello World!\n");
});

app.post("/users", (req,res) => {
    const username = req.body.username || '';
    const password = req.body.password || '';

    // validation
    if(!username || !password || users[username]) {
        res.status(400).send("Failed Validation\n");
    }

    let salt = crypto.randomBytes(128).toString('base64');

    let hash = crypto.pbkdf2Sync(password, salt, 10000, 512, 'sha512');

    users[username] = {salt , hash};

    res.sendStatus(201);
});

app.post("/auth", (req,res) => {
    const username = req.body.username;
    const password = req.body.password;

    // validation
    if(!username || !password || !users[username]) {
        res.sendStatus(400);
    }

    const { salt , hash } = users[username];

    const generatedHash = crypto.pbkdf2Sync(password, salt, 10000, 512, 'sha512');

    const valideHash = crypto.timingSafeEqual(generatedHash , hash);

    console.log(valideHash);

    res.sendStatus(valideHash ? 200 : 401);
});


app.listen(port, () => {
    console.log(`Server started on port: ${port}`);
});