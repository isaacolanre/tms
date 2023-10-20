var router = express.Router();

//Get agent account details and balance
//Post to self
router.get("/getwallet/details", function(req, res)
{
    try
    {
        var tid = req.headers.tid;
        try
        {
            if(tid.length !== 8)
            {
                var arr = [];
                /*var obj = new Object();
                obj.tid = tid;
                obj.amount = '0.0';
                obj.accountname = "LOGIN REQUIRED";
                obj.email = "NA";
                arr.push(obj);*/
                res.status(200).send(arr);
            }else
            {
                var qry = "SELECT * FROM walletbalance WHERE tid = $1";
                pool.query(qry, [tid], (err, result) => { 
                    if (err) 
                    {
                        logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                        res.status(500).send({"status": 500, "message": "Error Occured. Try Later."});
                    }
                    else
                    {
                        res.status(200).send(result.rows);
                    }
                });
            }
        }catch(e)
        {
            logger.info("Token Confirmation Error: " + e);
            return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Authorized."});
        }
    }catch(e)
    {
        logger.info(req.headers.tid + " is not authorize.");
        return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Authorized."});
    }
});

router.get("/getwallet/hacker", function(req, res)
{
    try
    {
        var tid = req.headers.tid;
        var email = req.headers.email;
        var token = req.headers.token;

        try
        {
            if(tid.length !== 8)
            {
                var arr = [];
                res.status(200).send(arr);
            }else
            {
                var qry = "SELECT * FROM tokens WHERE token = $1 AND username = $2";
                pool.query(qry, [token, email], (err, lol) => {
                    if (err) 
                    {
                        logger.info("tms TOKEN CHECK FAILED FOR " + req.clientIp);
                        //return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
                        return res.status(500).send([]);
                    }else
                    {
                        //if(lol.rows.length !== 1)
                        if(lol.rows === undefined || lol.rows.length !== 1)
                        {
                            logger.info("Kindly login again " + req.clientIp);
                            //return res.status(500).send({"status": 500, "message": "Token Issue"});
                            return res.status(500).send([]);
                        }else
                        {
                            var date1 = new Date();
                            var date2 = new Date(lol.rows[0].timestop);
                            var timeDiff = date1.getTime() - date2.getTime();
                            var dif = timeDiff / 1000;
                            if(dif >= 1)
                            {
                                logger.info("Time out. Please login again. " + req.clientIp);
                                //return res.status(500).send({"status": 500, "message": "Time Out. Please Login."});
                                return res.status(500).send([]);
                            }else
                            {
                                var qry = "SELECT * FROM walletbalance WHERE tid = $1";
                                pool.query(qry, [tid], (err, result) => { 
                                    if (err) 
                                    {
                                        logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                        //res.status(500).send({"status": 500, "message": "Error Occured. Try Later."});
                                        return res.status(500).send([]);
                                    }
                                    else
                                    {
                                        res.status(200).send(result.rows);
                                    }
                                });
                            }
                        }
                    }
                });
            }
        }catch(e)
        {
            logger.info("Token Confirmation Error: " + e);
            //return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Authorized."});
            return res.status(500).send([]);
        }
    }catch(e)
    {
        logger.info(req.headers.tid + " is not authorize.");
        //return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Authorized."});
        return res.status(500).send([]);
    }
});


router.get("/getalltxn/today/tid", function(req, res)
{
    var tid = req.headers.tid;
    try
    {
        var txn = "SELECT * FROM ejournal WHERE current_date_uzoezi = $1 AND terminal_id = $2 ORDER BY id DESC";
        pool.query(txn, [formatDateMessage(new Date()), tid], (err, transaction) => {
            if (err) 
            {
                logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                return res.status(500).send([]);
            }
            else
            {
                if(transaction.rows.length === 0)
                {
                    logger.info("Channels Ptad Insert. Ip: " + req.clientIp + "  " + new Date().toLocaleString() + ". By: user");
                    return res.status(200).send([]); 
                }else
                {
                    var len = transaction.rows.length;
                    var inc = 0;
                    var arr = [];
                    transaction.rows.forEach(function( trans ) {
                        inc = inc + 1;
                        var obj = new Object();
                        obj.id = trans.id;
                        obj.amount = trans.amount;
                        obj.terminal_id = trans.terminal_id;
                        if(trans.response_code === "00")
                            obj.status = "SUCCESSFUL";
                        else
                            obj.status = "NOT SUCCESSFUL";
                        obj.masked_pan = trans.masked_pan;
                        obj.rrn = trans.rrn;
                        obj.code = trans.response_code;
                        obj.type = trans.extras;
                        obj.time = trans.current_timestamp;
                        arr.push(obj);
                        if(inc === len)
                        {
                            logger.info("Channels Ptad Insert. Ip: " + req.clientIp + "  " + new Date().toLocaleString() + ". By: user");
                            return res.status(200).send(arr);  
                        }
                    });
                }										
            }
        });
    }catch(e)
    {
        logger.info(e + " is not authorize.");
        return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Authorized."});
    }
});

router.get("/getalltxn/today/all", function(req, res)
{
    try
    {
        var txn = "SELECT * FROM ejournal WHERE current_date_uzoezi = $1 ORDER BY id DESC";
        pool.query(txn, [formatDateMessage(new Date())], (err, transaction) => {
            if (err) 
            {
                logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                return res.status(500).send([]);
            }
            else
            {
                //console.log(transaction.rows)
                if(transaction.rows.length === 0)
                {
                    logger.info("Channels Ptad Insert. Ip: " + req.clientIp + "  " + new Date().toLocaleString() + ". By: user");
                    return res.status(200).send([]); 
                }else
                {
                    var len = transaction.rows.length;
                    var inc = 0;
                    var arr = [];
                    transaction.rows.forEach(function( trans ) {
                        inc = inc + 1;
                        var obj = new Object();
                        obj.id = trans.id;
                        obj.amount = trans.amount;
                        obj.terminal_id = trans.terminal_id;
                        if(trans.response_code === "00")
                            obj.status = "SUCCESSFUL";
                        else
                            obj.status = "NOT SUCCESSFUL";
                        obj.masked_pan = trans.masked_pan;
                        obj.rrn = trans.rrn;
                        obj.code = trans.response_code;
                        obj.type = trans.extras;
                        obj.time = trans.current_timestamp;
                        arr.push(obj);
                        if(inc === len)
                        {
                            logger.info("Channels Ptad Insert. Ip: " + req.clientIp + "  " + new Date().toLocaleString() + ". By: user");
                            return res.status(200).send(arr);  
                        }
                    });
                }									
            }
        });
    }catch(e)
    {
        logger.info(e + " is not authorize.");
        return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Authorized."});
    }
});

router.get("/daterange/:sd/:ed", function(req, res)
{
    try
    {
        var sd = req.params.sd;
        var ed = req.params.ed;
        var tid = req.headers.tid;
        var txn = "SELECT * FROM ejournal WHERE terminal_id = $1 AND current_date_uzoezi BETWEEN $2 AND $3 ORDER BY id DESC";
        pool.query(txn, [tid, sd, ed], (err, transaction) => {
            if (err) 
            {
                logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                return res.status(500).send([]);
            }
            else
            {
                if(transaction.rows.length < 1)
                {
                    logger.info("Channels Ptad Insert. Ip: " + req.clientIp + "  " + new Date().toLocaleString() + ". By: user");
                    return res.status(200).send([]); 
                }else
                {
                    var len = transaction.rows.length;
                    var inc = 0;
                    var arr = [];
                    transaction.rows.forEach(function( trans ) {
                        inc = inc + 1;
                        var obj = new Object();
                        obj.id = trans.id;
                        obj.amount = trans.amount;
                        obj.terminal_id = trans.terminal_id;
                        if(trans.response_code === "00")
                            obj.status = "SUCCESSFUL";
                        else
                            obj.status = "NOT SUCCESSFUL";
                        obj.masked_pan = trans.masked_pan;
                        obj.rrn = trans.rrn;
                        obj.code = trans.response_code;
                        obj.type = trans.extras;
                        obj.time = trans.current_timestamp;
                        arr.push(obj);
                        if(inc === len)
                        {
                            logger.info("Channels Ptad Insert. Ip: " + req.clientIp + "  " + new Date().toLocaleString() + ". By: user");
                            return res.status(200).send(arr);  
                        }
                    });
                }
            }
        });
    }catch(e)
    {
        logger.info(req.headers.username + " is not authorize.");
        return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Authorized."});
    }
});

router.post("/mobile/changepassword", function(req, res)
{
    try
    {
        var username = req.body.email;
        var oldpassword = req.body.oldpassword;
        var newpassword = req.body.newpassword;
        
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
                    bcrypt.compare(oldpassword, hash, function(err, results) {
                        if(results === true)
                        {
                            bcrypt.hash(newpassword, bcryptsaltRounds, function(err, hashnew) {
                                var qry2 =
                                    "UPDATE tms_users SET password = $1"
                                    + " WHERE username = $2";
                                pool.query(qry2, [hashnew, 
                                    username], (err, resul) => {
                                    if (err) 
                                    {
                                        console.log(err)
                                        logger.info("Database Issue. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                        res.status(500).send({"status": 500, "message": "Cannot Change Password. Retry Later."});
                                    }else
                                    {
                                        var mailOptions = {
                                            from: emailHeading, // sender address
                                            to: [result.rows[0].email], // list of receivers
                                            replyTo: replyTo,
                                            subject: "tms NOTIFICATION", // Subject line
                                            text: "YOU CHANGED YOUR PASSWORD\nIF THIS WAS NOT INITIATED BY YOU, CONTACT tms SUPPORT\nTHANK YOU", // plain text body with html format
                                        };
                                            
                                        transporter.sendMail(mailOptions, function(error, info){
                                            if (error) {
                                                logger.info(error);
                                            } else {
                                                logger.info('Email sent: ' + info.response);
                                            }
                                        });
                                        return res.status(200).send({"status": 200, "message": "Update Successful."});
                                    }
                                });
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
    }catch(e)
    {
        logger.info(e);
        logger.info("Having Issues with User Signup " + req.clientIp);
        res.status(500).send({"status": 500, "message": "Runtime error occurred. Try Later."});
    }
});

function formatDateMessage(date) 
{
    var year = date.getFullYear().toString();
    var month = (date.getMonth() + 101).toString().substring(1);
    var day = (date.getDate() + 100).toString().substring(1);
    return year + "-" + month + "-" + day;
}

router.get("/cardmore", function(req, res)
{
    try
    {
        var tid = req.headers.tid;
        var ref = req.headers.rrn;

        var txn = "SELECT * FROM frometranzact WHERE tid  = $1 AND ref = $2";
        pool.query(txn, [tid, ref], (err, transaction) => {
            if (err) 
            {
                logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                return res.status(500).send([]);
            }
            else
            {
                logger.info("All Terminals Successfully saved to " + req.clientIp + "  " + new Date().toLocaleString());
                res.status(200).send(transaction.rows);									
            }
        });
    }catch(e)
    {
        logger.info(req.headers.username + " is not authorize.");
        return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Authorized."});
    }
});

router.get("/agency/:sd/:ed", function(req, res)
{
    try
    {
        var tid = req.headers.tid;
        var sd = req.params.sd;
        var ed = req.params.ed;
        var txn = "SELECT * FROM frometranzact WHERE tousedate BETWEEN $1 AND $2 AND tid = $3 ORDER BY id DESC"
        pool.query(txn, [sd, ed, tid], (err, transaction) => {
            if (err) 
            {
                logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                return res.status(500).send([]);
            }
            else
            {
                logger.info("All Terminals Successfully saved to " + req.clientIp + "  " + new Date().toLocaleString());
                res.status(200).send(transaction.rows);								
            }
        });
    }catch(e)
    {
        logger.info(req.headers.username + " is not authorize.");
        return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Authorized."});
    }
});


module.exports.router = router;