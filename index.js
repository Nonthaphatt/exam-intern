const mysql = require('mysql');

const express = require('express');
const app = express();

const bcrypt = require('bcryptjs');

require("dotenv").config();
const host = process.env.HOST;
const user = process.env.USER;
const passWord = process.env.PASSWORD;
const dataBase = process.env.DATABASE;

app.listen(3000, () => console.log("Start service on port 3000"));
app.use(express.json())
app.use(express.urlencoded({ extended: true }))

var con = mysql.createConnection({
    host: host,
    user: user,
    password: passWord,
    database: dataBase,
});

const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_])[a-zA-Z\d\W_]{8,}$/;

app.get('/', async (req, res) => {
    res.redirect('/getUser')
});

app.post("/createUser", async (req, res) => {
    var { username, password, Fname, Lname, email } = req.body;
    if(!passwordPattern.test(password)){
        return res.status(401).json({ message: "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one special character and one digit." });
    }else{
        // change ' " to html code for cross side script
        username = username.replace(/"/g, "&#34;").replace(/'/g, "&#39;")
        Fname = Fname.replace(/"/g, "&#34;").replace(/'/g, "&#39;")
        Lname = Lname.replace(/"/g, "&#34;").replace(/'/g, "&#39;")
        email = email.replace(/"/g, "&#34;").replace(/'/g, "&#39;")
        // check username exist
        await con.query('SELECT UName FROM user WHERE UName = ?', [username], async function (err, result, fields) {
            if (err) {
                return res.status(401).json({ message: "can't connect db" });
            }
            if (result.length !== 0) {
                return res.status(401).json({ message: "this username used" });
            } else {
                // bcrypt
                const salt = await bcrypt.genSalt(10);
                const hashedPassword = await bcrypt.hash(password, salt);
                // create user
                con.query('INSERT INTO user(UName, FName, LName, Password, Email) VALUES (?, ?, ?, ?, ?)', [username, Fname, Lname, hashedPassword, email], (error, result, fields) => {
                    if (error) {
                        return res.status(401).json({ message: error });
                    }
                    return res.status(201).json({ message: "Register successfully" });
                })
            }
        });
    }
    
})

app.get('/getUser', async (req, res) => {
    // if has no get param get all
    if(!req.query.uid){
        con.query('SELECT UID,FName, LName, Email FROM user', async function (error, results, fields) {
            if (error) throw error;
            else return res.status(200).json(results);
        })
    }else{
        // has param select by id
        con.query('SELECT UID,FName, LName, Email FROM user  WHERE UID = ?', [req.query.uid], async function (error, results, fields) {
            if (error) throw error;
            if(results.length===0) return res.send('have no this UID')
            else return res.status(200).json(results);
        })
    }
});

app.put('/update', async (req, res) => {
    var { username, password, Fname, Lname, email } = req.body;
    // check has this user
    con.query("select UName, Password from user where UName = ?", [username], async function (err, result, fields) {

        if (err) return res.status(401).json({ message: "can't connect db0" });
        // like login
        if (result.length === 0) return res.status(401).json({ message: "Username or Password incorrect1" });
        const passwordMatch = await bcrypt.compare(password, result[0].Password);
        if (!passwordMatch) return res.status(401).json({ message: "Username or Password incorrect2" });

        else{
            // update data
            Fname = Fname.replace(/"/g, "&#34;").replace(/'/g, "&#39;")
            Lname = Lname.replace(/"/g, "&#34;").replace(/'/g, "&#39;")
            email = email.replace(/"/g, "&#34;").replace(/'/g, "&#39;")
             con.query('UPDATE user SET FName = ?, LName = ?, Email = ? WHERE UName = ?', [Fname, Lname, email, username], (error, result, fields) => {
                if (error) return res.status(401).json({ message: "Unable to update" })
                else return res.status(200).json({ message: "update data successfully" })
            })
        }

    });
   
});

app.delete('/delete', async (req, res) => {
    // find this user
    con.query('SELECT UID,FName, LName, Email FROM user  WHERE UID = ?', [req.query.uid], async function (error, results, fields) {
        if (error) throw error;
        // has no
        if(results.length===0) return res.status(401).json({ message: "have no this ID" })
        else{
            // delete user
            con.query('DELETE FROM user WHERE UID = ?', [req.params.uid], async function (error, results, fields) {
                if (error) return res.status(401).json({ message: "Unable to complete delete" })
                else return res.status(200).json({ message: "delete successfully" })
            })
        }
    })
    
});


