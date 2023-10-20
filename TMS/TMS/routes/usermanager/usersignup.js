var router = express.Router();

router.get("/user", function(req, res)
{
    try
    {
        var str = new Date().toLocaleString();
        var token = req.cookies.token_tcm;
        var username = req.cookies.username;
        try
        {
            var qry = "SELECT * FROM tokens WHERE token = $1 AND username = $2";
            pool.query(qry, [token, username], (err, result) => { 
                if (err) 
                {
                    logger.info("Database connection error: " + err + ". Username: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                    return res.redirect("/");
                }
                else
                {
                    if(result.rows.length !== 1)
                    {
                        logger.info("Incorrect Token Details. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                        res.redirect("/");
                    }else
                    {
                        if(result.rows[0].role !== "admin")
                        {
                            logger.info("Not authorized for. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                            return res.redirect("/tms/dashboard/show");
                        }
                        var response = result.rows[0];
                        var role = response.role;
                        var usertype = response.usertype;
                        logger.info("Spitting out new user to: " + req.clientIp + ". Time: " + new Date().toLocaleString());
                        return res.status(200).render("user/usersignup", {details: JSON.stringify(response), role: role, usertype, usertype});
                    }
                }
            });
        }catch(e)
        {
            logger.info("Token Confirmation Error");
            return res.redirect("/");
        }
    }catch(e)
    {
        logger.info(req.cookies.username + " is not authorize to view URL 3");
        return res.redirect("/");
    }
});

router.post("/user", function(req, res)
{
    try
    {
        console.log(req.body);
        console.log(req.cookies);
        var qry = "SELECT * FROM tokens WHERE token = $1 AND username = $2";
        pool.query(qry, [req.cookies.token_tcm, req.cookies.username], (err, result) => {
            if (err) 
            {
                logger.info("tms TOKEN CHECK FAILED FOR " + req.clientIp);
                return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
            }else
            {
                if(result.rows === undefined || result.rows.length !== 1)
                {
                    logger.info("Kindly login again " + req.clientIp);
                    return res.status(500).send({"status": 500, "message": "Token Issue"});
                }else if(result.rows[0].role !== "admin")
                {
                    logger.info(req.cookies.username + " not qualified to access endpoint. Client: " + req.clientIp);
                    return res.status(500).send({"status": 500, "message": "Not Qualified to Access Endpoint"});
                }else
                {
                    var date1 = new Date();
                    var date2 = new Date(result.rows[0].timestop);
                    var timeDiff = date1.getTime() - date2.getTime();
                    var dif = timeDiff / 1000;
                    if(dif >= 1)
                    {
                        logger.info("Time out. Please login again. " + req.clientIp);
                        return res.status(500).send({"status": 500, "message": "Time Out. Please Login."});
                    }else
                    {
                        bcrypt.hash(req.body.password, bcryptsaltRounds, function(err, hash) {
                            var qry2 = "INSERT INTO tms_users " + 
                            "(fullname, username, addedby, role, email, status, password, " + 
                            "justset, usertype, approved, approvedby, datecreated, namecreated, bankname, tmo, phonenumber) " + 
                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                            pool.query(qry2, [req.body.fullname, req.body.username, req.cookies.username, 
                                req.body.role, req.body.email, "active", 
                                hash, "true", req.body.usertype, 
                                "true", "tms", new Date().toLocaleString(), result.rows[0].fullname, req.body.bankname, req.body.tmo, req.body.phonenumber], (err, resul) => {
                                if (err) 
                                {
                                    console.log(err);
                                    logger.info("Database Issue. User: " + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                    res.status(500).send({"status": 500, "message": "Cannot Signup. User Later."});
                                }else
                                {
                                    if(req.body.role === "agent")
                                    {
                                        var qry2 = "INSERT INTO agentaccount " + 
                                            "(username, lastbalance, balance, lastmodifiedby, blocked, txnrules, typeofuser) " + 
                                            "VALUES ($1, $2, $3, $4, $5, $6, $7)";
                                        pool.query(qry2, [req.body.username, "0.00", "0.00",
                                            req.cookies.username, "false", "1000###70???30", "agent"], (err, resul) => {
                                            if (err) 
                                            {
                                                logger.info("Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                res.status(500).send({"status": 500, "message": "Cannot Signup. Retry Later."});
                                            }else
                                            {
                                                logger.info("Agent Setup successfully.....");
                                            }
                                        });
                                    }else if(req.body.role === "merchant")
                                    {
                                        var qry2 = "INSERT INTO agentaccount " + 
                                            "(username, lastbalance, balance, lastmodifiedby, blocked, txnrules, typeofuser) " + 
                                            "VALUES ($1, $2, $3, $4, $5, $6, $7)";
                                        pool.query(qry2, [req.body.username, "0.00", "0.00",
                                            req.cookies.username, "false", "1000###0???0", "merchant"], (err, resul) => {
                                            if (err) 
                                            {
                                                logger.info("Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                res.status(500).send({"status": 500, "message": "Cannot Signup. Retry Later."});
                                            }else
                                            {
                                                logger.info("Agent Setup successfully.....");
                                            }
                                        });
                                    }
                                    var mailOptions = {
                                        from: emailHeading, // sender address
                                        to: [req.body.email], // list of receivers
                                        bcc: "sanusi.segun@etopng.com", // Blind Copy
                                        replyTo: replyTo,
                                        subject: "TMS NOTIFICATION", // Subject line
                                        text: "SUCCESSFUL SIGNUP\n\n" + "Your Username: " + req.body.username
                                        //+ "\nYour Password: " + req.body.password +
                                        + "\nYour Name: " + req.body.fullname +
                                        + "\nYour Phonenumber: " + req.body.phonenumber +
                                        "\nEndeavour to change your password immediately. \nWelcome to tms", // plain text body with html format
                                    };
                                    transporter.sendMail(mailOptions, function(error, info){
                                        if (error) {
                                            logger.info(error);
                                        } else {
                                            logger.info('Email sent: ' + info.response);
                                        }
                                    });
                                    return res.status(200).send({"status": 200, "message": "Successful Signup."});
                                }
                            });
                        });
                    }
                }
            }
        });
    }catch(e)
    {
        logger.info(e);
        logger.info("Having Issues with User Signup " + req.clientIp);
        res.status(500).send({"status": 500, "message": "Runtime error occurred. Try Later."});
    }
});

router.get("/admin", function(req, res)
{
    try
    {
        var str = new Date().toLocaleString();
        var token = req.cookies.token_tcm;
        var username = req.cookies.username;
        try
        {
            var qry = "SELECT * FROM tokens WHERE token = $1 AND username = $2";
            pool.query(qry, [token, username], (err, result) => { 
                if (err) 
                {
                    logger.info("Database connection error: " + err + ". Username: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                    return res.redirect("/");
                }
                else
                {
                    if(result.rows.length !== 1)
                    {
                        logger.info("Incorrect Token Details. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                        res.redirect("/");
                    }else
                    {
                        if(result.rows[0].role !== "admin")
                        {
                            logger.info("Not authorized for. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                            return res.redirect("/tms/dashboard/show");
                        }
                        var response = result.rows[0];
                        var role = response.role;
                        var usertype = response.usertype;
                        logger.info("Spitting out new user to: " + req.clientIp + ". Time: " + new Date().toLocaleString());
                        return res.status(200).render("user/adminsignup", {details: JSON.stringify(response), role: role, usertype, usertype});
                    }
                }
            });
        }catch(e)
        {
            logger.info("Token Confirmation Error");
            return res.redirect("/");
        }
    }catch(e)
    {
        logger.info(req.cookies.username + " is not authorize to view URL 3");
        return res.redirect("/");
    }
});

router.post("/admin", function(req, res)
{
    try
    {
        var qry = "SELECT * FROM tokens WHERE token = $1 AND username = $2";
        pool.query(qry, [req.cookies.token_tcm, req.cookies.username], (err, result) => {
            if (err) 
            {
                logger.info("tms TOKEN CHECK FAILED FOR " + req.clientIp);
                return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
            }else
            {
                if(result.rows === undefined || result.rows.length !== 1)
                {
                    logger.info("Kindly login again " + req.clientIp);
                    return res.status(500).send({"status": 500, "message": "Token Issue"});
                }else if(result.rows[0].role !== "admin")
                {
                    logger.info(req.cookies.username + " not qualified to access endpoint. Client: " + req.clientIp);
                    return res.status(500).send({"status": 500, "message": "Not Qualified to Access Endpoint"});
                }else
                {
                    var date1 = new Date();
                    var date2 = new Date(result.rows[0].timestop);
                    var timeDiff = date1.getTime() - date2.getTime();
                    var dif = timeDiff / 1000;
                    if(dif >= 1)
                    {
                        logger.info("Time out. Please login again. " + req.clientIp);
                        return res.status(500).send({"status": 500, "message": "Time Out. Please Login."});
                    }else
                    {
                        bcrypt.hash(req.body.password, bcryptsaltRounds, function(err, hash) {
                            var qry2 = "INSERT INTO tms_users " + 
                            "(fullname, username, addedby, role, email, status, password, " + 
                            "justset, usertype, approved, approvedby, datecreated, namecreated) " + 
                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";
                            pool.query(qry2, [req.body.fullname, req.body.username, req.cookies.username, 
                                "admin", req.body.email, "active", 
                                hash, "true", "", 
                                "true", "tms", new Date().toLocaleString(), result.rows[0].fullname], (err, resul) => {
                                if (err) 
                                {
                                    logger.info("Database Issue. User: " + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                    res.status(500).send({"status": 500, "message": "Cannot Signup. Retry Later."});
                                }else
                                {
                                    var mailOptions = {
                                        from: emailHeading, // sender address
                                        to: [req.body.email], // list of receivers
                                        replyTo: replyTo,
                                        subject: "TMS NOTIFICATION", // Subject line
                                        text: "SUCCESSFUL SIGNUP\n\n" + "Your Username: " + req.body.username
                                        + "\nYour Name: " + req.body.fullname +
                                        "\nEndeavour to change your password immediately.", // plain text body with html format
                                    };
                                        
                                    transporter.sendMail(mailOptions, function(error, info){
                                        if (error) {
                                            logger.info(error);
                                        } else {
                                            logger.info('Email sent: ' + info.response);
                                        }
                                    });
                                    return res.status(200).send({"status": 200, "message": "Successful Signup."});
                                }
                            });
                        });
                    }
                }
            }
        });
    }catch(e)
    {
        logger.info(e);
        logger.info("Having Issues with User Signup " + req.clientIp);
        res.status(500).send({"status": 500, "message": "Runtime error occurred. Try Later."});
    }
});

router.post("/mobile", function(req, res)
{
    try
    {
        var role = "agent";
        var usertype = "agent";
        bcrypt.hash(req.body.password, bcryptsaltRounds, function(err, hash) {
            var qry2 = "INSERT INTO tms_users " + 
            "(fullname, username, addedby, role, email, status, password, " + 
            "justset, usertype, approved, approvedby, datecreated, namecreated, bankname, tmo, phonenumber, bvn, lga, address, dob) " + 
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)";
            pool.query(qry2, [req.body.fullname, req.body.username, "MOBILE", 
                role, req.body.email, "active", 
                hash, "true", usertype, 
                "true", "tms", new Date().toLocaleString(), "MOBILE", 
                req.body.bankname, req.body.tmo, req.body.phonenumber,
                req.body.bvn, req.body.lga, req.body.address, req.body.dob], (err, resul) => {
                if (err) 
                {
                    res.status(500).send({"status": 500, "message": "Cannot Signup. Retry Later."});
                }else
                {
                    var qry2 = "INSERT INTO newsignup " + 
                        "(email, fullname, role, phonenumber, status) " + 
                        "VALUES ($1, $2, $3, $4, $5)";
                    pool.query(qry2, [req.body.email, req.body.fullname, "agent", req.body.phonenumber, "NOT ASSIGNED"], (err, resul) => {
                        if (err) 
                        {
                            res.status(500).send({"status": 500, "message": "Cannot Signup. Retry Later."});
                        }else
                        {
                            var mailOptions = {
                                from: emailHeading, // sender address
                                to: [req.body.email], // list of receivers
                                bcc: "sanusi.segun@etopng.com", // Blind Copy
                                replyTo: replyTo,
                                subject: "TMS NOTIFICATION", // Subject line
                                text: "SUCCESSFUL SIGNUP\n\n" + "Your Username: " + req.body.username
                                //+ "\nYour Password: " + req.body.password +
                                + "\nYour Name: " + req.body.fullname +
                                + "\nYour Phonenumber: " + req.body.phonenumber +
                                "\nEndeavour to change your password immediately. \nWelcome to tms", // plain text body with html format
                            };
                            transporter.sendMail(mailOptions, function(error, info){
                                if (error) {
                                    logger.info(error);
                                } else {
                                    logger.info('Email sent: ' + info.response);
                                }
                            });
                            return res.status(200).send({"status": 200, "message": "Successful Signup."});
                        }
                    });
                }
            });
        });
    }catch(e)
    {
        logger.info(e);
        logger.info("Having Issues with User Signup " + req.clientIp);
        res.status(500).send({"status": 500, "message": "Runtime error occurred. Try Later."});
    }
});


module.exports.router = router;