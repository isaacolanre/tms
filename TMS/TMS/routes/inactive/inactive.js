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
                        return res.status(200).render("inactive/inactive", {details: JSON.stringify(response), role: role, usertype, usertype});
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
            logger.info("Token Confirmation Error");
            return res.status(500).send({"status": 500, "message": "An Error Occurred. Token Issue."});
        }
    }catch(e)
    {
        logger.info(req.cookies.username + " is not authorize to view URL 3");
        return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Authorized."});
    }
});

function formatDt(date) {
    return date.toString().slice(0, 24);
}

router.post("/view", function(req, res)
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
                    var qry = "SELECT * FROM terminalconfiguration";
                    pool.query(qry, (err, result) => { 
                        if (err) 
                        {
                            logger.info("Database connection error: " + err + ". Time: " +  new Date().toLocaleString());
                            return res.status(500).send([]);
                        }
                        else
                        {
                            if(result.rows.length < 1)
                            {
                                logger.info("No Terminal Available. Time: " +  new Date().toLocaleString());
                                return res.status(500).send([]);
                            }else
                            {
                                var arr = [];
                                var tot = result.rows.length;
                                var chk = 0;
                                var per = 0;
                                result.rows.forEach(function(transaction) {
                                    var txn = "SELECT * FROM ejournal WHERE terminal_id = $1 ORDER BY id DESC LIMIT 1";
                                    pool.query(txn, [transaction.tid], (err, ejorn) => {
                                        if (err) 
                                        {
                                            logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                                            return;
                                        }
                                        else
                                        {
                                            chk = chk + 1;
                                            //logger.info("CHECKER: " + chk);
                                            //logger.info("TOTAL: " + tot);
                                            if(1)
                                            {
                                                var ldate = "";
                                                if(ejorn.rows.length < 1)
                                                    ldate = "2020-04-02";
                                                else
                                                    ldate = ejorn.rows[0].current_date_uzoezi;
                                                var cdate = formatDateMessage(new Date());
                                                const date1 = new Date(ldate);
                                                const date2 = new Date(cdate);
                                                const diffTime = Math.abs(date2 - date1);
                                                const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)); 

                                                //console.log(diffDays);
                                                if(diffDays > 2)
                                                {
                                                    per = per + 1;
                                                    var b = "";
                                                    if(ejorn.rows.length < 1)
                                                        b = "NA";
                                                    else
                                                        b = formatDt(ejorn.rows[0].current_timestamp);
                                                    //console.log(b);
                                                    var obj = new Object();
                                                    obj.tid = transaction.tid;
                                                    obj.merchantname = transaction.merchantname;
                                                    obj.merchantaddress = transaction.merchantaddress;
                                                    obj.bank = transaction.bankname;
                                                    obj.days = diffDays - 1;
                                                    obj.tmo = transaction.tmo;
                                                    obj.lasttxn = b;
                                                    arr.push(obj);
                                                }
                                                if(chk === tot)
                                                {
                                                    logger.info("INSIDE THE MAIN GUY");
                                                    return res.status(200).send(JSON.stringify(arr));
                                                }else
                                                    return;
                                            }
                                        }
                                    });
                                });
                            }
                        }
                    });
                }
            }
        });
    }catch(e)
    {
        logger.info("Token Confirmation Error: " + e);
        return res.status(500).send([]);
    }
});


module.exports.router = router;