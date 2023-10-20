var router = express.Router();

router.get("/show", function(req, res)
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
                        if(result.rows[0].role !== "user")
                        {
                            logger.info("Not authorized for. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                            return res.redirect("/tms/dashboard/show");
                        }
                        var response = result.rows[0];
                        var role = response.role;
                        var usertype = response.usertype;
                        logger.info("Spitting out all users to: " + req.clientIp + ". Time: " + new Date().toLocaleString());
                        return res.status(200).render("credit/credits", {details: JSON.stringify(response), role: role, usertype, usertype});
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

router.get("/getalldata/:startdate/:enddate", function(req, res)
{
    console.log("Inside get all transactions credit");
    req.socket.setKeepAlive();
    var str = new Date().toLocaleString();
    var token = req.cookies.token_tcm;
    var username = req.cookies.username;
    var startdate = req.params.startdate;
    var enddate = req.params.enddate;
    // console.log(startdate);
    // console.log(enddate);
    try
    {
        var qry = "SELECT * FROM tokens WHERE token = $1 AND username = $2";
        pool.query(qry, [token, username], (err, result) => { 
            if (err) 
            {
                logger.info("Database connection error: " + err + ". Username: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                return res.status(500).send([]);
            }
            else
            {
                if(result.rows.length !== 1)
                {
                    logger.info("Incorrect Token Details. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                    return res.status(500).send([]);
                }else
                {
                    const txn = "SELECT * FROM walletcredit WHERE tousedate BETWEEN $1 AND $2 order by id desc";
                    pool.query(txn, [startdate, enddate], (err,  comms) => {    
                        if (err) 
                        {
                            logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                            return res.status(500).send([]);
                        }
                        else
                        {
                            logger.info("All Transactions Successfully saved to " + req.clientIp + "  " + new Date().toLocaleString());
                            logger.info("Length of data: " + comms.rows);
                            //console.log(comms.rows)
                            return res.status(200).send(comms.rows);									
                        }
                    });
                }
            }
        });
    }catch(e)
    {
        logger.info("Token Confirmation Error");
        return res.status(500).send({"status": 500, "message": "An Error Occurred. Token Issue."});
    }
});

router.get("/getalldataextra", function(req, res)
{
    console.log("Inside get all transactions credit");
    req.socket.setKeepAlive();
    var str = new Date().toLocaleString();
    var token = req.cookies.token_tcm;
    var username = req.cookies.username;
    // console.log(startdate);
    // console.log(enddate);
    try
    {
        var qry = "SELECT * FROM tokens WHERE token = $1 AND username = $2";
        pool.query(qry, [token, username], (err, result) => { 
            if (err) 
            {
                logger.info("Database connection error: " + err + ". Username: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                return res.status(500).send([]);
            }
            else
            {
                if(result.rows.length !== 1)
                {
                    logger.info("Incorrect Token Details. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                    return res.status(500).send([]);
                }else
                {
                    const txn = "SELECT * FROM walletcredit WHERE status = $1 order by id desc";
                    pool.query(txn, ["false"], (err,  comms) => {    
                        if (err) 
                        {
                            logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                            return res.status(500).send([]);
                        }
                        else
                        {
                            logger.info("All Transactions Successfully saved to " + req.clientIp + "  " + new Date().toLocaleString());
                            logger.info("Length of data: " + comms.rows);
                            //console.log(comms.rows)
                            return res.status(200).send(comms.rows);									
                        }
                    });
                }
            }
        });
    }catch(e)
    {
        logger.info("Token Confirmation Error");
        return res.status(500).send({"status": 500, "message": "An Error Occurred. Token Issue."});
    }
});

router.post("/show", function(req, res)
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
                //if(result.rows.length !== 1)
                if(result.rows === undefined || result.rows.length !== 1)
                {
                    logger.info("Kindly login again " + req.clientIp);
                    return res.status(500).send({"status": 500, "message": "Token Issue"});
                }else if(result.rows[0].role !== "user" || result.rows[0].usertype === "viewonly")
                {
                    logger.info(req.headers.username + " not qualified to access endpoint. Client: " + req.clientIp);
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
                        //console.log(req.body)
                        //email, amount, initiator, timeinitiated, approvedby, timeapproved, status
                        var qry2 = "INSERT INTO walletcredit " + 
                            "(email, amount, initiator," +
                                "timeinitiated, status) " + 
                            "VALUES ($1, $2, $3, $4, $5)";
                        pool.query(qry2, [req.body.email, req.body.amount,
                            req.cookies.username, datetime(), "false"], (err, resul) => {
                            if (err) 
                            {
                                logger.info("Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                res.status(500).send({"status": 500, "message": "Cannot Signup. Retry Later."});
                            }else
                            {
                                return res.status(200).send({"status": 200, "message": "Successfully Added."});
                            }
                        });
                    }
                }
            }
        });
    }catch(e)
    {
        logger.info(e);
        logger.info("Having Issues with User Delete " + req.clientIp);
        res.status(500).send({"status": 500, "message": "Runtime error occurred. Try Later."});
    }
});

router.put("/update/:id", function(req, res)
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
                //if(result.rows.length !== 1)
                if(result.rows === undefined || result.rows.length !== 1)
                {
                    logger.info("Kindly login again " + req.clientIp);
                    return res.status(500).send({"status": 500, "message": "Token Issue"});
                }else if(result.rows[0].role !== "user" || result.rows[0].usertype === "viewonly")
                {
                    logger.info(req.headers.username + " not qualified to access endpoint. Client: " + req.clientIp);
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
                        //console.log(req.body)
                        //email, amount, initiator, timeinitiated, approvedby, timeapproved, status
                        var qry2 =
                            "UPDATE walletcredit SET approvedby = $1, timeapproved = $2, status = $3" + 
                            " WHERE id = $4";
                        pool.query(qry2, [req.cookies.username, datetime(), true, req.params.id], (err, resul) => {
                            if (err) 
                            {
                                console.log(err)
                                logger.info("Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                res.status(500).send({"status": 500, "message": "Cannot Update. Retry Later."});
                            }else
                            {
                                console.log(req.body);
                                var qry = "SELECT * FROM walletbalance WHERE username = $1";
                                pool.query(qry, [req.body.email], (err, love) => { 
                                    if (err) 
                                    {
                                        logger.info("12... Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                        res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                    }
                                    else
                                    {
                                        if(love.rows === undefined || love.rows.length == 0)
                                        {
                                            logger.info("34.. Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                            return res.status(500).send({"status": 500, "message": "No Funds Available"});
                                        }else
                                        {
                                            var totAgentAmount = (parseFloat(love.rows[0].amount) + parseFloat(req.body.amount)).toFixed(2);
                                            var qry2 =
                                                "UPDATE walletbalance SET amount = $1 WHERE username = $2";
                                            pool.query(qry2, [totAgentAmount, req.body.email], (err, resul) => {
                                                if (err) 
                                                {
                                                    logger.info("55.. Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                    return res.status(500).send({"status": 500, "message": "An Error Occurred..."});
                                                }else
                                                {
                                                    var preBal = 0.00;
                                                    var newBal = 0.00;
                                                    preBal = love.rows[0].amount;
                                                    newBal = parseFloat(totAgentAmount);
                                                    var waA = "INSERT INTO walletactivies " + 
                                                        "(username, amount, oldamount, newamount, transmode, transinfo, status)" + 
                                                        "VALUES ($1, $2, $3, $4, $5, $6, $7)";
                                                    pool.query(waA, [req.body.email, req.body.amount, preBal, newBal, 
                                                        "CREDIT", "MANUAL CREDIT FROM: " + req.cookies.username + ". TMS.", "SUCCESS"], (err, resul) => {
                                                        if (err) 
                                                        {
                                                            logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                            return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                        }else
                                                        {
                                                            return res.status(200).send({"status": 200, "message": "Update Successful."});
                                                        }
                                                    });
                                                }
                                            });
                                        }
                                    }
                                });
                            }
                        });
                    }
                }
            }
        });
    }catch(e)
    {
        logger.info(e);
        logger.info("Having Issues with User Delete " + req.clientIp);
        res.status(500).send({"status": 500, "message": "Runtime error occurred. Try Later."});
    }
});

module.exports.router = router;