var router = express.Router();

router.get("/user", function(req, res)
{
    try
    {
        res.clearCookie('token_tcm');
        res.clearCookie('username');
        logger.info("Spitting out user login to: " + req.clientIp + ". Time: " + new Date().toLocaleString());
        res.status(200).render("login/userlogin", {})
    }catch(e)
    {
        logger.info("User login could not be served to " + req.clientIp);
        res.redirect("/");
    };
});

router.get("/admin", function(req, res)
{
    try
    {
        res.clearCookie('token_tcm');
        res.clearCookie('username');
        logger.info("Spitting out login to: " + req.clientIp + ". Time: " + new Date().toLocaleString());
        res.status(200).render("login/adminlogin", {})
    }catch(e)
    {
        logger.info("Home could not be served to " + req.clientIp);
        res.redirect("/");
    };
});

router.get("/merchant", function(req, res)
{
    try
    {
        res.clearCookie('token_tcm');
        res.clearCookie('username');
        logger.info("Spitting out login to: " + req.clientIp + ". Time: " + new Date().toLocaleString());
        res.status(200).render("login/merchantlogin", {})
    }catch(e)
    {
        logger.info("Home could not be served to " + req.clientIp);
        res.redirect("/");
    };
});

router.get("/agent", function(req, res)
{
    try
    {
        res.clearCookie('token_tcm');
        res.clearCookie('username');
        logger.info("Spitting out login to: " + req.clientIp + ". Time: " + new Date().toLocaleString());
        res.status(200).render("login/agentlogin", {})
    }catch(e)
    {
        logger.info("Home could not be served to " + req.clientIp);
        res.redirect("/");
    };
});

router.get("/recover", function(req, res)
{
    try
    {
        res.clearCookie('token_tcm');
        res.clearCookie('username');
        logger.info("Spitting out password recovery to: " + req.clientIp + ". Time: " + new Date().toLocaleString());
        res.status(200).render("login/recovery", {});
    }catch(e)
    {
        logger.info("Recovery could not be served to " + req.clientIp);
        res.redirect("/");
    }
});

router.post("/updatingsn", function(req, res)
{
    console.log(req.body);
    var username = req.body.username;
    var mposserialnumber = req.body.mposserialnumber;
    var qry2 =
        "UPDATE tms_users SET mposserialnumber = $1"
        + " WHERE username = $2";
    pool.query(qry2, [mposserialnumber, username], (err, resul) => {
        if (err) 
        {
            console.log(err)
            res.status(500).send({"status": 500, "message": "Serial Mismatch. Contact Support."});
        }else
        {
            return res.status(200).send({"status": 200, "message": "UPDATE OK."});
        }
    });
});

router.get("/updatingtp", function(req, res)
{
    console.log(req.headers);
    var username = req.headers.email;
    var transferpin = req.headers.transferpin;
    var qry2 =
        "UPDATE tms_users SET transferpin = $1"
        + " WHERE username = $2";
    pool.query(qry2, [transferpin, username], (err, resul) => {
        if (err) 
        {
            console.log(err)
            res.status(500).send({"status": 500, "message": "Serial Mismatch. Contact Support."});
        }else
        {
            return res.status(200).send({"status": 200, "message": "UPDATE OK."});
        }
    });
});

//VERSION 3 UPWARDS
router.post("/mobileverify", function(req, res)
{
    var str = new Date().toLocaleString();
    var username = req.body.username;
    var password = req.body.password;
    var usertype = req.body.usertype;
    var phoneserialnumber = req.body.phoneserialnumber;
    var count = req.body.count; //Used to track login time

    //logger.info(req.body);
    if((username.length < 1 || username.length > 100) || (password.length < 1 || password.length > 100))
    {
        logger.info("Wrong Login Params: " + JSON.stringify(req.body));
        return res.status(500).send({"status": 500, "message": "Wrong Parameters."});
    }
    try
    {
        if(username === 'nelsonulonna@gmail.com' ||
            username === 'ogunkoyaseyefunmi@gmail.com' ||
            username === 'obileyetemitope4@gmail.com' ||
            username === 'temmyfree2rhyme@gmail.com' ||
            username === 'inyassjamiu@gmail.com' ||
            username === 'mercyblis@gmail.com' ||
            username === 'ekeka500@gmail.com' ||
            username === 'gloryoboh34@gmail.com' ||
            username === 'ajibolajbl07@gmail.com' ||
            username === 'uchegiftxp@gmail.com'
            )
        {
            console.log("OUTSTANDING DEBT");
            return res.status(500).send({"status": 500, "message": "Outstanding Debt."});
        }else if(count > 3)
        {
            //Block User
            logger.info(username + " has been blocked");
            const query =
                "UPDATE tms_users SET status = $1, blockedreason = $2"
                + " WHERE username = $3 AND role = $4";
            pool.query(query, ["blocked", "Provided Wrong Login Details For 3 Times", username, usertype], (err,  results) => {    
                if (err) 
                {
                    logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                    return res.status(500).send({"status": 500, "message": "Cannot login."});
                }
                else
                {
                    logger.info("tms Block Success. Ip: " + req.clientIp + "  " + new Date().toLocaleString() + ". For: " + username);
                    return res.status(500).send({"status": 400, "message": "You have been Blocked. Contact Admin"});
                }
            });
        }else
        {
            logger.info("tms Login By: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
            var qry = "SELECT * FROM tms_users WHERE username = $1";
            pool.query(qry, [username], (err, result) => { 
                if (err) 
                {
                    logger.info("Database connection error: " + err + ". Username: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                    res.status(500).send({"status": 500, "message": "Incorrect Login Details."});
                }
                else
                {
                    if(result.rows === undefined || result.rows.length == 0)
                    {
                        logger.info("USER: Incorrect Login Details. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                        res.status(500).send({"status": 500, "message": "Incorrect Login Details."});
                    }else
                    {
                        var hash = result.rows[0].password;
                        hash = hash.replace(/^\$2y(.+)$/i, '$2a$1');
                        bcrypt.compare(password, hash, function(err, results) {
                            if(results === true)
                            {
                                if(result.rows[0].status !== "active"
                                    || result.rows[0].approved === "false")
                                {
                                    logger.info("Contact Admin. You have been blocked: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                    return res.status(500).send({"status": 500, "message": "Unauthorized User. Contact Admin."});
                                }else
                                {
                                    var qry2 = "DELETE FROM tokens WHERE username = $1";
                                    pool.query(qry2, [username], (err, result2) => {
                                        if (err) 
                                        {
                                            logger.info("Token User Database Issue " + req.clientIp + ". Time" +  new Date().toLocaleString() + ". For: " + username);
                                            return res.status(500).send({"status": 500, "message": "Login Not Successful."});
                                        }else
                                        {
                                            var dt = new Date();
                                            var startDate = dt.toLocaleString();
                                            var endDate = new Date(dt.getTime() + 120*60000).toLocaleString();
                                            var parse = username + ":" + Math.floor((Math.random() * 100000000) + 1) + ":" + dt.toLocaleString();
                                            var token = encryptData(parse, passwordtoken);
                                            var qry2 = "INSERT INTO tokens (username, token, timestart, timestop, fullname, role, justset, email, usertype, tmo) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";
                                            pool.query(qry2, [username, token, startDate, endDate, result.rows[0].fullname, 
                                                result.rows[0].role, result.rows[0].justset, result.rows[0].email, result.rows[0].usertype, result.rows[0].tmo], (err, resul) => {
                                                if (err) 
                                                {
                                                    logger.info("Database Issue. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                    res.status(500).send({"status": 500, "message": "Cannot login."});
                                                }else
                                                {
                                                    var sn = result.rows[0].phoneserialnumber;
                                                    console.log("Store serial number: " + sn);
                                                    console.log("Incoming serial number: " + phoneserialnumber);
                                                    if(sn === undefined || sn === null || sn.length === 0)
                                                    {
                                                        var qry2 =
                                                            "UPDATE tms_users SET phoneserialnumber = $1"
                                                            + " WHERE username = $2";
                                                        pool.query(qry2, [phoneserialnumber, username], (err, resul) => {
                                                            if (err) 
                                                            {
                                                                console.log(err)
                                                                res.status(500).send({"status": 500, "message": "Serial Mismatch. Contact Support."});
                                                            }else
                                                            {
                                                                var mailOptions = {
                                                                    from: emailHeading, // sender address
                                                                    to: [result.rows[0].email], // list of receivers
                                                                    replyTo: replyTo,
                                                                    subject: "TMS NOTIFICATION", // Subject line
                                                                    text: "SUCCESSFUL LOGIN", // plain text body with html format
                                                                };
                                                                    
                                                                transporter.sendMail(mailOptions, function(error, info){
                                                                    if (error) {
                                                                        logger.info(error);
                                                                    } else {
                                                                        logger.info('Email sent: ' + info.response);
                                                                    }
                                                                });

                                                                res.status(200).send({"status": 200, 
                                                                    "message": "Login Success.", 
                                                                    "phoneserialnumber": result.rows[0].phoneserialnumber,
                                                                    "mposserialnumber": result.rows[0].mposserialnumber,
                                                                    "transferpin": result.rows[0].transferpin,
                                                                    "token": token
                                                                });
                                                            }
                                                        });
                                                    }else if(result.rows[0].phoneserialnumber === phoneserialnumber ||
                                                        result.rows[0].phoneserialnumber !== phoneserialnumber)
                                                    {
                                                        var mailOptions = {
                                                            from: emailHeading, // sender address
                                                            to: [result.rows[0].email], // list of receivers
                                                            replyTo: replyTo,
                                                            subject: "TMS NOTIFICATION", // Subject line
                                                            text: "SUCCESSFUL LOGIN", // plain text body with html format
                                                        };
                                                            
                                                        transporter.sendMail(mailOptions, function(error, info){
                                                            if (error) {
                                                                logger.info(error);
                                                            } else {
                                                                logger.info('Email sent: ' + info.response);
                                                            }
                                                        });

                                                        res.status(200).send({"status": 200, 
                                                            "message": "Login Success.", 
                                                            "phoneserialnumber": result.rows[0].phoneserialnumber,
                                                            "mposserialnumber": result.rows[0].mposserialnumber,
                                                            "transferpin": result.rows[0].transferpin,
                                                            "token": token
                                                        });
                                                    }else
                                                    {
                                                        res.status(500).send({"status": 500, "message": "Serial Mismatch. Use Original Device."});
                                                    }
                                                }
                                            });
                                        }
                                    });
                                }
                            }else
                            {
                                logger.info("Incorrect Login Details. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                res.status(500).send({"status": 500, "message": "Incorrect Login Details."});
                            }
                        });
                    }
                }
            });
        }
    }catch(e)
    {
        logger.info("Login Error");
        res.status(500).send({"status": 500, "message": "Server Error. Retry Later"});
    }
});

router.get("/devicereset", function(req, res)
{
    var str = new Date().toLocaleString();
    var username = req.headers.email;
    var phoneserialnumber = req.headers.phoneserialnumber;
    var phonenumber = req.headers.phonenumber;
    logger.info(req.headers);
    var txn = "SELECT * FROM tms_users where username = $1";
    pool.query(txn, [username], (err, users) => {
        if (err) 
        {
            console.log(err)
            res.status(500).send([]);
        }else
        {
            if(users.rows === undefined || users.rows.length == 0)
            {
                console.log("EMAIL NOT REGISTERED");
                res.status(500).send({"status": 500, "message": "Email not registered"});
            }else
            {
                var qry2 = "DELETE FROM devicereset where email = $1";
                pool.query(qry2, [username], (err, resul) => {
                    if (err) 
                    {
                        console.log("DELETING OLD RECORDS FAILED");
                        res.status(500).send({"status": 500, "message": "Delete Failed. Try Later"});
                    }else
                    {
                        var pin = randomstring.generate({
                            length: 6,
                            charset: 'numeric'
                        });
                        var qry2 = "INSERT INTO devicereset " + 
                            "(email, serialnumber, phonenumber, pin) " + 
                            "VALUES ($1, $2, $3, $4)";
                        pool.query(qry2, [username, phoneserialnumber, phonenumber, pin], (err, resul) => {
                            if (err) 
                            {
                                console.log(err);
                                res.status(500).send({"status": 500, "message": "Error Occurred. Retry Later."});
                            }else
                            {
                                var mailOptions = {
                                    from: emailHeading, // sender address
                                    to: username, // list of receivers
                                    replyTo: replyTo,
                                    subject: "TMS RESET NOTIFICATION", // Subject line
                                    text: "YOU HAVE REQUESTED TO RESET YOUR DEVICE THAT IS TIED TO " + username + "\n" 
                                        + "YOUR PIN IS: " + pin + "\nPLEASE LET US KNOW IF THIS WAS NOT INITIATED BY YOU.", // plain text body with html format
                                };
                                transporter.sendMail(mailOptions, function(error, info){
                                    if (error) {
                                        logger.info(error);
                                    } else {
                                        logger.info('Email sent: ' + info.response);
                                    }
                                });
                                return res.status(200).send({"status": 200, "message": "Successfully Added."});
                            }
                        });
                    }
                });
            }
        }
    });
});

router.get("/confirmpin", function(req, res)
{
    var str = new Date().toLocaleString();
    var username = req.headers.email;
    var pin = req.headers.pin;
    logger.info(req.headers);
    var txn = "SELECT * FROM devicereset where email = $1";
    pool.query(txn, [username], (err, users) => {
        if (err) 
        {
            console.log(err)
            res.status(500).send([]);
        }else
        {
            if(users.rows === undefined || users.rows.length == 0)
            {
                console.log("EMAIL NOT REGISTERED");
                res.status(500).send({"status": 500, "message": "Email not registered"});
            }else
            {
                if(users.rows[0].pin === pin)
                {
                    var qry2 =
                        "UPDATE tms_users SET phoneserialnumber = $1, mposserialnumber = $2, transferpin = $3"
                        + " WHERE username = $4";
                    pool.query(qry2, ["", "",
                        "", username], (err, resul) => {
                        if (err) 
                        {
                            console.log(err);
                            res.status(500).send({"status": 500, "message": "Cannot Update. Retry Later."});
                        }else
                        {
                            var mailOptions = {
                                from: emailHeading, // sender address
                                to: username, // list of receivers
                                replyTo: replyTo,
                                subject: "TMS RESET CONFIRMATION", // Subject line
                                text: "YOUR DEVICE RESET WAS SUCCESSFUL. THANK YOU\n" 
                                    + "\nPLEASE LET US KNOW IF THIS WAS NEVER INITIATED BY YOU.", // plain text body with html format
                            };
                            transporter.sendMail(mailOptions, function(error, info){
                                if (error) {
                                    logger.info(error);
                                } else {
                                    logger.info('Email sent: ' + info.response);
                                }
                            });
                            res.status(200).send({"status": 200, "message": "Update Successful."});
                        }
                    });
                }else
                {
                    console.log("WRONG PIN ENTERED...");
                    res.status(500).send({"status": 500, "message": "Wrong Pin Entered"});
                }
            }
        }
    });
});

router.get("/activities/:sd/:ed", function(req, res)
{
    var sd = req.params.sd;
    var ed = req.params.ed;
    var tid = req.headers.tid;
    var txn = "SELECT * FROM walletactivies WHERE tid = $1 AND tousedate BETWEEN $2 AND $3  ORDER BY id DESC";
    pool.query(txn, [tid, sd, ed], (err, transaction) => {
        if (err) 
        {
            console.log(err)
            res.status(500).send([]);
        }else
        {
            res.status(200).send(transaction.rows);
        }
    });
});


router.post("/webverify", function(req, res)
{
    var str = new Date().toLocaleString();
    var username = req.body.username;
    var password = req.body.password;
    var usertype = req.body.usertype;
    var count = req.body.count; //Used to track login time

    //logger.info(req.body);
    if((username.length < 1 || username.length > 100) || (password.length < 1 || password.length > 100))
    {
        logger.info("Wrong Login Params: " + JSON.stringify(req.body));
        return res.status(500).send({"status": 500, "message": "Wrong Parameters."});
    }
    try
    {
        if(count > 3)
        {
            //Block User
            logger.info(username + " has been blocked");
            const query =
                "UPDATE tms_users SET status = $1, blockedreason = $2"
                + " WHERE username = $3 AND role = $4";
            pool.query(query, ["blocked", "Provided Wrong Login Details For 3 Times", username, usertype], (err,  results) => {    
                if (err) 
                {
                    logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                    return res.status(500).send({"status": 500, "message": "Cannot login."});
                }
                else
                {
                    logger.info("tms Block Success. Ip: " + req.clientIp + "  " + new Date().toLocaleString() + ". For: " + username);
                    return res.status(500).send({"status": 400, "message": "You have been Blocked. Contact Admin"});
                }
            });
        }else
        {
            logger.info("tms Login By: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
            var qry = "SELECT * FROM tms_users WHERE username = $1";
            pool.query(qry, [username], (err, result) => { 
            //var qry = "SELECT * FROM tms_users WHERE username = $1 AND role = $2";
            //pool.query(qry, [username, usertype], (err, result) => { 
                if (err) 
                {
                    logger.info("Database connection error: " + err + ". Username: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                    res.status(500).send({"status": 500, "message": "Incorrect Login Details."});
                }
                else
                {
                    if(result.rows === undefined || result.rows.length == 0)
                    {
                        logger.info("USER: Incorrect Login Details. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                        res.status(500).send({"status": 500, "message": "Incorrect Login Details."});
                    }else
                    {
                        var hash = result.rows[0].password;
                        hash = hash.replace(/^\$2y(.+)$/i, '$2a$1');
                        bcrypt.compare(password, hash, function(err, results) {
                            if(results === true)
                            {
                                if(result.rows[0].status !== "active"
                                    || result.rows[0].approved === "false")
                                {
                                    logger.info("Contact Admin. You have been blocked: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                    return res.status(500).send({"status": 500, "message": "Unauthorized User. Contact Admin."});
                                }
                                var qry2 = "DELETE FROM tokens WHERE username = $1";
                                pool.query(qry2, [username], (err, result2) => {
                                    if (err) 
                                    {
                                        logger.info("Token User Database Issue " + req.clientIp + ". Time" +  new Date().toLocaleString() + ". For: " + username);
                                        return res.status(500).send({"status": 500, "message": "Login Not Successful."});
                                    }else
                                    {
                                        var dt = new Date();
                                        var startDate = dt.toLocaleString();
                                        var endDate = new Date(dt.getTime() + 120*60000).toLocaleString();
                                        var parse = username + ":" + Math.floor((Math.random() * 100000000) + 1) + ":" + dt.toLocaleString();
                                        var token = encryptData(parse, passwordtoken);
                                        var qry2 = "INSERT INTO tokens (username, token, timestart, timestop, fullname, role, justset, email, usertype, tmo) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";
                                        pool.query(qry2, [username, token, startDate, endDate, result.rows[0].fullname, 
                                            result.rows[0].role, result.rows[0].justset, result.rows[0].email, result.rows[0].usertype, result.rows[0].tmo], (err, resul) => {
                                            if (err) 
                                            {
                                                logger.info("Database Issue. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                res.status(500).send({"status": 500, "message": "Cannot login."});
                                            }else
                                            {
                                                var mailOptions = {
                                                    from: emailHeading, // sender address
                                                    to: [result.rows[0].email], // list of receivers
                                                    replyTo: replyTo,
                                                    subject: "TMS NOTIFICATION", // Subject line
                                                    text: "SUCCESSFUL LOGIN", // plain text body with html format
                                                };
                                                    
                                                transporter.sendMail(mailOptions, function(error, info){
                                                    if (error) {
                                                        logger.info(error);
                                                    } else {
                                                        logger.info('Email sent: ' + info.response);
                                                    }
                                                });

                                                let options = {
                                                    maxAge: 1000 * 60 * 120, // would expire after 120 minutes
                                                    //httpOnly: true, // The cookie only accessible by the web server
                                                    //signed: true // Indicates if the cookie should be signed
                                                }

                                                res.cookie('token_tcm', token, options);
                                                res.cookie('username', username, options);
                                                res.status(200).send({status: 200, message: "Login Success."});
                                            }
                                        });
                                    }
                                });
                            }else
                            {
                                logger.info("Incorrect Login Details. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                res.status(500).send({"status": 500, "message": "Incorrect Login Details."});
                            }
                        });
                    }
                }
            });
        }
    }catch(e)
    {
        logger.info("Login Error");
        res.status(500).send({"status": 500, "message": "Server Error. Retry Later"});
    }
});

router.post("/verify", function(req, res)
{
    return res.status(500).send({"status": 500, "message": "Please Download Version 1.0.3 From Playstore."});
});


router.post("/forgetpassword", function(req, res)
{
    try
    {
        var email = req.body.email;
		var qry = "SELECT * FROM tms_users WHERE email = $1";
		pool.query(qry, [email], (err, result) => { 
			if (err) 
			{
				logger.info("Database connection error: " + err + ". Email: " + req.body.email + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
				res.status(500).send({"status": 500, "message": "An error occurred."});
			}
			else
			{
                if(result.rows === undefined || result.rows.length !== 1)
				{
					logger.info("Email Address does not exist. " + req.clientIp);
					return res.status(500).send({"status": 500, "message": "Email Address does not exist."});
				}else
				{
                    var newpassword = randomstring.generate({
                        length: 20,
                        charset: 'alphanumeric'
                    });
                    bcrypt.hash(newpassword, bcryptsaltRounds, function(err, hash) {
                        var qry2 =
                            "UPDATE tms_users SET password = $1"
                            + " WHERE email = $2";
                        pool.query(qry2, [hash, 
                            email], (err, resul) => {
                            if (err) 
                            {
                                res.status(500).send({"status": 500, "message": "Cannot Recover Password. Retry Later."});
                            }else
                            {
                                var mailOptions = {
                                    from: emailHeading, // sender address
                                    to: [email], // list of receivers
                                    replyTo: replyTo,
                                    subject: "TMS PASSWORD RESET", // Subject line
                                    text: "LOGIN DETAILS\n\n" + "Your Email: " + email
                                    + "\nYour Password: " + newpassword +
                                    "\nEndeavour to change your password immediately.", // plain text body with html format
                                };  
                                transporter.sendMail(mailOptions, function(error, info){
                                    if (error) {
                                        logger.info(error);
                                    } else {
                                        logger.info('Email sent: ' + info.response);
                                    }
                                });
                                return res.status(200).send({"status": 200, "message": "Password Recovery Successful."});
                            }
                        });
                    });
				}
			}
		});
	}catch(e)
    {
        logger.info(e);
        logger.info("Having Issues with Password Recovery " + req.clientIp);
        res.status(500).send({"status": 500, "message": "Runtime error occurred. Try Later."});
    }
});

router.all("*", function(req, res)
{
    logger.info("In login No route");
    logger.info(req.url);
    logger.info("Wrong URL. Redirecting to home. From: " + req.clientIp + ". Time: " + new Date().toLocaleString());
    res.redirect("/");
});

module.exports.router = router;