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
                        var response = result.rows[0];
                        var role = response.role;
                        var usertype = response.usertype;
                        logger.info("Spitting out all users to: " + req.clientIp + ". Time: " + new Date().toLocaleString());
                        return res.status(200).render("settlement/agencyinstant", {details: JSON.stringify(response), role: role, usertype, usertype});
                    }
                }
            });
        }catch(e)
        {
            logger.info("Token Confirmation Error: " + e);
            return res.redirect("/");
        }
    }catch(e)
    {
        logger.info(req.cookies.username + " is not authorize to view URL 3");
        return res.redirect("/");
    }
});

router.get("/getalltids", function(req, res)
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
                    return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
                }
                else
                {
                    if(result.rows.length !== 1)
                    {
                        logger.info("Incorrect Token Details. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                        return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
                    }else
                    {
                        var qry2;
                        if(result.rows[0].role === "user")
                        {
                            console.log("USERS");
                            qry2 = "SELECT * FROM terminalconfiguration";
                        }else
                        {
                            var rr = result.rows[0].role;
                            //console.log(rr);
                            if(rr === "merchant")
                                qry2 = "SELECT * FROM terminalconfiguration where ownerusername = '" + username + "'";
                            else if(rr === "agent")
                                qry2 = "SELECT * FROM terminalconfiguration where ownerusername = '" + username + "'";
                            else if(rr === "super-agent")
                                qry2 = "SELECT * FROM terminalconfiguration where superagent = '" + username + "'";
                            else if(rr === "ptsp")
                                qry2 = "SELECT * FROM terminalconfiguration where ptsp = '" + username + "'";
                            else if(rr === "bank")
                                qry2 = "SELECT * FROM terminalconfiguration where bankusername = '" + username + "'";
                            else
                                qry2 = "SELECT * FROM terminalconfiguration where ownerusername = '" + username + "'";
                        }
                        pool.query(qry2, (err, resul) => {
                            if (err) 
                            {
                                logger.info("Database Issue. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                res.status(500).send({"status": 500, "message": "Cannot Signup. Retry Later."});
                            }else
                            {
                                return res.status(200).send({"status": 200, "message": JSON.stringify(resul.rows)});
                            }
                        });
                    }
                }
            });
        }catch(e)
        {
            logger.info("Token Confirmation Error: " + e);
            return res.status(500).send({"status": 500, "message": "An Error Occurred. Token Issue."});
        }
    }catch(e)
    {
        logger.info(req.cookies.username + " is not authorize to view URL 3");
        return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Authorized."});
    }
});

function formatDateMessage(date) 
{
    var year = date.getFullYear().toString();
    var month = (date.getMonth() + 101).toString().substring(1);
    var day = (date.getDate() + 100).toString().substring(1);
    return year + "-" + month + "-" + day;
}

router.get("/getallinstantvalue", function(req, res)
{
    req.socket.setKeepAlive();
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
                    var txn = "SELECT * FROM agencyinstant WHERE tousedate = $1 OR status = $2 ORDER BY id ASC";
                                pool.query(txn, [formatDateMessage(new Date()), "NOT SETTLED"], (err, comms) => {
                        if (err) 
                        {
                            logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                            return res.status(500).send([]);
                        }
                        else
                        {
                            logger.info("All Terminals Successfully saved to " + req.clientIp + "  " + new Date().toLocaleString());
                            res.status(200).send(JSON.stringify(comms.rows));									
                        }
                    });
                }
            }
        });
    }catch(e)
    {
        logger.info("Token Confirmation Error: " + e);
        return res.status(500).send({"status": 500, "message": "An Error Occurred. Token Issue."});
    }
});

router.get("/getAllToday/:lastId", function(req, res)
{
    req.socket.setKeepAlive();
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
                    var lastId = req.params.lastId;
                    var txn = "SELECT * FROM agencyinstant WHERE id > $1 ORDER BY id ASC";
                    pool.query(txn, [lastId], (err, comms) => {   
                        if (err) 
                        {
                            logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                            return res.status(500).send([]);
                        }
                        else
                        {
                            logger.info("All Terminals Successfully saved to " + req.clientIp + "  " + new Date().toLocaleString());
                            res.status(200).send(JSON.stringify(comms.rows));									
                        }
                    });
                }
            }
        });
    }catch(e)
    {
        logger.info("Token Confirmation Error: " + e);
        return res.status(500).send({"status": 500, "message": "An Error Occurred. Token Issue."});
    }
});

router.post("/getbydaterange", function(req, res)
{
    req.socket.setKeepAlive();
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
                    //Start here
                    var sd = req.body.sd;
                    var ed = req.body.ed;
                    var txn = "SELECT * FROM agencyinstant WHERE tousedate BETWEEN $1 AND $2";
                    pool.query(txn, [sd, ed], (err, transaction) => {
                        if (err) 
                        {
                            logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                            return res.status(500).send([]);
                        }
                        else
                        {
                            logger.info("Channels Ptad Insert. Ip: " + req.clientIp + "  " + new Date().toLocaleString() + ". By: user");
                            return res.status(200).send(JSON.stringify(transaction.rows));
                        }
                    });
                }
            }
        });
    }catch(e)
    {
        logger.info("Token Confirmation Error: " + e);
        return res.status(500).send({"status": 500, "message": "An Error Occurred. Token Issue."});
    }
});

router.get("/transactiondetails/:id", function(req, res)
{
    req.socket.setKeepAlive();
    var str = new Date().toLocaleString();
    var token = req.cookies.token_tcm;
    var username = req.cookies.username;
    var param = req.params.id;
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
                    var txn = "SELECT * FROM agencyinstant WHERE id = $1";
                                pool.query(txn, [param], (err, comms) => {
                        if (err) 
                        {
                            logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                            return res.status(500).send([]);
                        }
                        else
                        {
                            logger.info("All Terminals Successfully saved to " + req.clientIp + "  " + new Date().toLocaleString());
                            res.status(200).send(JSON.stringify(comms.rows));									
                        }
                    });
                }
            }
        });
    }catch(e)
    {
        logger.info("Token Confirmation Error: " + e);
        return res.status(500).send({"status": 500, "message": "An Error Occurred. Token Issue."});
    }
});

router.get("/makerapproval/:id", function(req, res)
{
    req.socket.setKeepAlive();
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
                    var id = req.params.id;
                    var name = result.rows[0].fullname;
                    
                    var qry2 =
                        "UPDATE agencyinstant SET makername = $1, makerapprovaltime = $2 WHERE id = $3";
                    pool.query(qry2, [name, datetime(), id], (err, resul) => {
                        if (err) 
                        {
                            console.log(err)
                            logger.info("Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                            res.status(500).send({"status": 500, "message": "Cannot Update. Retry Later."});
                        }else
                        {
                            var qry = "SELECT * FROM agencyinstant WHERE id = $1";
                            pool.query(qry, [id], (err, transact) => { 
                                if (err) 
                                {
                                    logger.info("Database connection error: " + err + ". Username: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                    return res.status(500).send({"status": 500, "message": "Cannot Update. Retry Later."});
                                }
                                else
                                {
                                    var transaction = transact.rows[0];
                                    if(transaction.checkername !== null)
                                    {
                                        var currentTime = new Date();
                                        var checkTime = new Date();
                                        checkTime.setHours(7,0,0); // 7 am

                                        if(currentTime > checkTime)
                                        {
                                            checkTime = new Date();
                                            checkTime.setHours(13,0,0); // 1 pm
                                            if(currentTime > checkTime)
                                            {
                                                checkTime = new Date();
                                                checkTime.setHours(19,0,0); // 7 pm
                                                if(currentTime > checkTime)
                                                {
                                                    checkTime = new Date(new Date().getTime()+(9*60*60*1000));
                                                }
                                            }
                                        }

                                        var amt = transaction.amount;
                                        var t = parseFloat(amt);
                                        var msc = ((transaction.msc/100) * t).toFixed(2);
                                        if(msc > 1000)
                                            msc = 1000;
                                        
                                        var stamp = 0.00;
                                        if(parseFloat(transaction.amount) >= 10000)
                                            stamp = parseFloat(transaction.stampduty);

                                        var iv = ((transaction.instantvaluepercentage/100) * t).toFixed(2);
                                        var amount = parseFloat(amt) - parseFloat(msc) - parseFloat(iv) - stamp;
                                        
                                        var qry2 =
                                            "UPDATE agencyinstant SET status = $1, lastretry = $2 WHERE id = $3";
                                        pool.query(qry2, ["QUEUED", datetime(), id], (err, resul) => {
                                            if (err) 
                                            {
                                                console.log(err)
                                                logger.info("Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                res.status(500).send({"status": 500, "message": "Cannot Update. Retry Later."});
                                            }else
                                            {
                                                var qry = "SELECT * FROM agencyinstantpayment WHERE usertype = $1";
                                                pool.query(qry, [transaction.usertype], (err, ivp) => { 
                                                    if (err) 
                                                    {
                                                        logger.info("Database connection error: " + err + ". Username: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                        return res.status(500).send({"status": 500, "message": "Cannot Update. Retry Later."});
                                                    }
                                                    else
                                                    {
                                                        if(ivp.rows.length < 1)
                                                        {
                                                            var qry2 = "INSERT INTO agencyinstantpayment " + 
                                                                "(tid, amount, accountname, accountbankcode, accountnumber, bankname, status, nextqueue, usertype) " + 
                                                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)";
                                                            pool.query(qry2, [transaction.tid, amount, transaction.accountname,
                                                                transaction.accountbankcode, transaction.accountnumber, transaction.bankname, 
                                                                "QUEUED", checkTime, transaction.usertype], (err, resul) => {
                                                                if (err) 
                                                                {
                                                                    logger.info("2. Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                    return res.status(500).send({"status": 500, "message": "Cannot Signup. Retry Later."});
                                                                }else
                                                                {
                                                                    return res.status(200).send({"status": 200, "message": "Successfully Added."});
                                                                }
                                                            });
                                                        }else
                                                        {
                                                            var invp = ivp.rows[0];
                                                            var amt = 0.00;
                                                            if(invp.status === "QUEUED")
                                                                amt = amount + parseFloat(invp.amount);
                                                            else
                                                                amt = amount;
                                                            var qry2 =
                                                                "UPDATE agencyinstantpayment SET amount = $1, accountname = $2, accountbankcode = $3, " + 
                                                                "accountnumber = $4, bankname = $5, status = $6, nextqueue = $7, tid = $8 WHERE usertype = $9";
                                                            pool.query(qry2, [amt, transaction.accountname,
                                                                transaction.accountbankcode, transaction.accountnumber, transaction.bankname, 
                                                                "QUEUED", checkTime, transaction.tid, transaction.usertype], (err, resul) => {
                                                                if (err) 
                                                                {
                                                                    logger.info("Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                    return res.status(500).send({"status": 500, "message": "Cannot Update. Retry Later."});
                                                                }else
                                                                {
                                                                    return res.status(200).send({"status": 200, "message": "Update Successful."});
                                                                }
                                                            });
                                                            
                                                        }
                                                    }
                                                });
                                            }
                                        });
                                    }else
                                    {
                                        return res.status(200).send({"status": 200, "message": "Successfully Added."});
                                    }
                                }
                            });
                        }
                    });
                }
            }
        });
    }catch(e)
    {
        logger.info("Token Confirmation Error: " + e);
        return res.status(500).send({"status": 500, "message": "An Error Occurred. Token Issue."});
    }
});

router.get("/checkerapproval/:id", function(req, res)
{
    req.socket.setKeepAlive();
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
                    var id = req.params.id;
                    var name = result.rows[0].fullname;
                    
                    var qry2 =
                        "UPDATE agencyinstant SET checkername = $1, checkerapprovaltime = $2 WHERE id = $3";
                    pool.query(qry2, [name, datetime(), id], (err, resul) => {
                        if (err) 
                        {
                            console.log(err)
                            logger.info("Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                            res.status(500).send({"status": 500, "message": "Cannot Update. Retry Later."});
                        }else
                        {
                            var qry = "SELECT * FROM agencyinstant WHERE id = $1";
                            pool.query(qry, [id], (err, transact) => { 
                                if (err) 
                                {
                                    logger.info("Database connection error: " + err + ". Username: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                    return res.status(500).send({"status": 500, "message": "Cannot Update. Retry Later."});
                                }
                                else
                                {
                                    var transaction = transact.rows[0];
                                    if(transaction.makername !== null)
                                    {
                                        var currentTime = new Date();
                                        var checkTime = new Date();
                                        checkTime.setHours(7,0,0); // 7 am

                                        if(currentTime > checkTime)
                                        {
                                            checkTime = new Date();
                                            checkTime.setHours(13,0,0); // 1 pm
                                            if(currentTime > checkTime)
                                            {
                                                checkTime = new Date();
                                                checkTime.setHours(19,0,0); // 7 pm
                                                if(currentTime > checkTime)
                                                {
                                                    checkTime = new Date(new Date().getTime()+(9*60*60*1000));
                                                }
                                            }
                                        }

                                        var amt = transaction.amount;
                                        var t = parseFloat(amt);
                                        var msc = ((transaction.msc/100) * t).toFixed(2);
                                        if(msc > 1000)
                                            msc = 1000;
                                        
                                        var stamp = 0.00;
                                        if(parseFloat(transaction.amount) >= 10000)
                                            stamp = parseFloat(transaction.stampduty);

                                        var iv = ((transaction.instantvaluepercentage/100) * t).toFixed(2);
                                        var amount = parseFloat(amt) - parseFloat(msc) - parseFloat(iv) - stamp;
                                        
                                        var qry2 =
                                            "UPDATE agencyinstant SET status = $1, lastretry = $2 WHERE id = $3";
                                        pool.query(qry2, ["QUEUED", datetime(), id], (err, resul) => {
                                            if (err) 
                                            {
                                                console.log(err)
                                                logger.info("Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                res.status(500).send({"status": 500, "message": "Cannot Update. Retry Later."});
                                            }else
                                            {
                                                var qry = "SELECT * FROM agencyinstantpayment WHERE usertype = $1";
                                                pool.query(qry, [transaction.usertype], (err, ivp) => { 
                                                    if (err) 
                                                    {
                                                        logger.info("Database connection error: " + err + ". Username: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                        return res.status(500).send({"status": 500, "message": "Cannot Update. Retry Later."});
                                                    }
                                                    else
                                                    {
                                                        if(ivp.rows.length < 1)
                                                        {
                                                            var qry2 = "INSERT INTO agencyinstantpayment " + 
                                                                "(tid, amount, accountname, accountbankcode, accountnumber, bankname, status, nextqueue, usertype) " + 
                                                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)";
                                                            pool.query(qry2, [transaction.tid, amount, transaction.accountname,
                                                                transaction.accountbankcode, transaction.accountnumber, transaction.bankname, 
                                                                "QUEUED", checkTime, transaction.usertype], (err, resul) => {
                                                                if (err) 
                                                                {
                                                                    logger.info("2. Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                    return res.status(500).send({"status": 500, "message": "Cannot Signup. Retry Later."});
                                                                }else
                                                                {
                                                                    return res.status(200).send({"status": 200, "message": "Successfully Added."});
                                                                }
                                                            });
                                                        }else
                                                        {
                                                            var invp = ivp.rows[0];
                                                            var amt = 0.00;
                                                            if(invp.status === "QUEUED")
                                                                amt = amount + parseFloat(invp.amount);
                                                            else
                                                                amt = amount;
                                                            var qry2 =
                                                                "UPDATE agencyinstantpayment SET amount = $1, accountname = $2, accountbankcode = $3, " + 
                                                                "accountnumber = $4, bankname = $5, status = $6, nextqueue = $7, tid = $8 WHERE usertype = $9";
                                                            pool.query(qry2, [amt, transaction.accountname,
                                                                transaction.accountbankcode, transaction.accountnumber, transaction.bankname, 
                                                                "QUEUED", checkTime, transaction.tid, transaction.usertype], (err, resul) => {
                                                                if (err) 
                                                                {
                                                                    logger.info("Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                    return res.status(500).send({"status": 500, "message": "Cannot Update. Retry Later."});
                                                                }else
                                                                {
                                                                    return res.status(200).send({"status": 200, "message": "Update Successful."});
                                                                }
                                                            });
                                                            
                                                        }
                                                    }
                                                });
                                            }
                                        });
                                    }else
                                    {
                                        return res.status(200).send({"status": 200, "message": "Successfully Added."});
                                    }
                                }
                            });
                        }
                    });
                }
            }
        });
    }catch(e)
    {
        logger.info("Token Confirmation Error: " + e);
        return res.status(500).send({"status": 500, "message": "An Error Occurred. Token Issue."});
    }
});

module.exports.router = router;