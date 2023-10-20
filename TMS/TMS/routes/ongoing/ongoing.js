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
                        return res.status(200).render("ongoing/ongoing", {details: JSON.stringify(response), role: role, usertype, usertype});
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

router.get("/getallongoing", function(req, res)
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
                    var txn = "SELECT * FROM ejournal WHERE current_date_uzoezi = $1 ORDER BY id ASC";
                                pool.query(txn, [formatDateMessage(new Date())], (err, comms) => {
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
                    var txn = "SELECT * FROM ejournal WHERE id > $1 ORDER BY id ASC";
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
                    var sd = req.body.sd;
                    var ed = req.body.ed;
                    var txn = "SELECT * FROM ejournal WHERE current_date_uzoezi BETWEEN $1 AND $2";
                    pool.query(txn, [sd, ed], (err, transaction) => {
                        if (err) 
                        {
                            logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                            return res.status(500).send([]);
                        }
                        else
                        {
                            const data = transaction.rows;
                            const fileName = 'transactions'
                            const exportType = 'xls'
                            const result = exportFromJSON({
                                data,
                                fileName,
                                exportType,
                                processor (content, type, fileName) {
                                    switch (type) {
                                        case 'txt':
                                            res.setHeader('Content-Type', 'text/plain')
                                            break
                                        case 'json':
                                            res.setHeader('Content-Type', 'text/plain')
                                            break
                                        case 'csv':
                                            res.setHeader('Content-Type', 'text/csv')
                                            break
                                        case 'xls':
                                            res.setHeader('Content-Type', 'application/vnd.ms-excel')
                                            break
                                    }
                                    res.setHeader('Content-disposition', 'attachment;filename=' + fileName)
                                    return content
                                }
                            });
                            var filen = randomstring.generate({
                                            length: 12,
                                            charset: 'alphabetic'
                                        });
                            filen = username + filen + ".xls";
                            var file = path.join(__dirname + '/../../public/downloads/' + filen);
                            fs.writeFile(file, result, function (err) {
                                if (err)
                                {
                                    logger.info("Channels Ptad Insert. Ip: " + req.clientIp + "  " + new Date().toLocaleString() + ". By: user");
                                    res.status(500).send(filen);
                                }else
                                {
                                    logger.info("Channels Ptad Insert. Ip: " + req.clientIp + "  " + new Date().toLocaleString() + ". By: user");
                                    res.status(200).send(filen);
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