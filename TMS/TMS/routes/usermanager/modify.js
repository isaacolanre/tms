const { hash } = require("bcrypt");

var router = express.Router();

router.get("/changepassword", function(req, res)
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
                        var response = result.rows[0];
                        var role = response.role;
                        var usertype = response.usertype;
                        logger.info("Spitting out change password to: " + req.clientIp + ". Time: " + new Date().toLocaleString());
                        return res.status(200).render("user/changepassword", {details: JSON.stringify(response), role: role, usertype, usertype});
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

router.post("/changepassword", function(req, res)
{
    try
    {
        var token = req.cookies.token_tcm;
        var username = req.cookies.username;
        var qry = "SELECT * FROM tokens WHERE token = $1 AND username = $2";
        pool.query(qry, [token, username], (err, result) => {
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
                        var qry = "SELECT * FROM tms_users WHERE username = $1 AND role = $2";
                        var role = result.rows[0].role;
                        pool.query(qry, [username, role], (err, result) => { 
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
                                    bcrypt.compare(req.body.oldpassword, result.rows[0].password, function(err, results) {
                                        if(results === true)
                                        {
                                            if(result.rows[0].status !== "active"
                                                || result.rows[0].approved === "false")
                                            {
                                                logger.info("Contact Admin. You have been blocked: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                return res.redirect("/");
                                            }
                                            bcrypt.hash(req.body.newpassword, bcryptsaltRounds, function(err, hash) {
                                                var qry2 =
                                                    "UPDATE tms_users SET password = $1"
                                                    + " WHERE username = $2 AND role = $3";
                                                pool.query(qry2, [hash, 
                                                    username, role], (err, resul) => {
                                                    if (err) 
                                                    {
                                                        console.log(err)
                                                        logger.info("Database Issue. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                        res.status(500).send({"status": 500, "message": "Cannot Change Password. Retry Later."});
                                                    }else
                                                    {
                                                        return res.status(200).send({"status": 200, "message": "Update Successful."});
                                                    }
                                                });
                                            });
                                        }else
                                        {
                                            logger.info("Incorrect Old Password Details. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                            res.status(500).send({"status": 500, "message": "Incorrect Old Password."});
                                        }
                                    });
                                }
                            }
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

router.get("/modify", function(req, res)
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
                        var response = result.rows[0];
                        var role = response.role;
                        var usertype = response.usertype;
                        logger.info("Spitting out modify to: " + req.clientIp + ". Time: " + new Date().toLocaleString());
                        return res.status(200).render("user/modify", {details: JSON.stringify(response), role: role, usertype, usertype});
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

router.post("/modify", function(req, res)
{
    try
    {
        var token = req.cookies.token_tcm;
        var username = req.cookies.username;
        var qry = "SELECT * FROM tokens WHERE token = $1 AND username = $2";
        pool.query(qry, [token, username], (err, result) => {
            if (err) 
            {
                logger.info("tms TOKEN CHECK FAILED FOR " + req.clientIp);
                return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
            }else
            {
                //if(result.rows.length !== 1)
                if(result.rows === undefined || result.rows.length !== 1)
                {
                    logger.info("Kindly login again " + req.clientIp);
                    return res.status(500).send({"status": 500, "message": "Token Issue"});
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
                        console.log(req.body)
                        var qry2 =
                            "UPDATE tms_users SET fullname = $1, email = $2"
                            + " WHERE username = $3";
                        pool.query(qry2, [req.body.fullname, req.body.email, 
                            username], (err, resul) => {
                            if (err) 
                            {
                                logger.info("Database Issue. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                res.status(500).send({"status": 500, "message": "Cannot Signup. Retry Later."});
                            }else
                            {
                                return res.status(200).send({"status": 200, "message": "Update Successful."});
                            }
                        });
                    }
                }
            }
        });
    }catch(e)
    {
        logger.info(e);
        logger.info("Having Issues with User Update " + req.clientIp);
        res.status(500).send({"status": 500, "message": "Runtime error occurred. Try Later."});
    }
});

module.exports.router = router;