var router = express.Router();

router.get("/superagents/agents", function(req, res)
{
    try
    {
        var tid = req.headers.tid;
        var email = req.headers.email;
        var token = req.headers.token;
        try
        {
            if(tid === null || email === null || token === null)
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
                        return res.status(500).send([]);
                    }else
                    {
                        if(lol.rows === undefined || lol.rows.length !== 1)
                        {
                            logger.info("Kindly login again " + req.clientIp);
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
                                return res.status(500).send([]);
                            }else
                            {
                                if(lol.rows[0].username !== email)
                                {
                                    logger.info("Username Dont Match. " + req.clientIp);
                                    return res.status(500).send([]);
                                }else if(lol.rows[0].role !== "user" && lol.rows[0].role !== "agent"
                                    && lol.rows[0].role !== "super-agent" && lol.rows[0].role !== "ptsp")
                                {
                                    logger.info("Not a valid User. " + req.clientIp);
                                    return res.status(500).send([]);
                                }else
                                {   
                                    var sqry = "";
                                    if(lol.rows[0].role === "user")
                                    {
                                        sqry = "SELECT * FROM terminalconfiguration WHERE email = $1";
                                    }else if(lol.rows[0].role === "agent")
                                    {
                                        sqry = "SELECT * FROM terminalconfiguration WHERE ownerusername = $1";
                                    }else if(lol.rows[0].role === "super-agent")
                                    {
                                        sqry = "SELECT * FROM terminalconfiguration WHERE superagent = $1";
                                    }else if(lol.rows[0].role === "ptsp")
                                    {
                                        sqry = "SELECT * FROM terminalconfiguration WHERE ptsp = $1";
                                    }
                                    pool.query(sqry, [email], (err, data) => {
                                        if (err) 
                                        {
                                            logger.info("tms TOKEN CHECK FAILED FOR " + req.clientIp);
                                            return res.status(500).send([]);
                                        }else
                                        {
                                            logger.info("DATA EXPORTED FOR: " + req.clientIp);
                                            return res.status(200).send({"status": 200, "message": data.rows});
                                        }
                                    });
                                }
                            }
                        }
                    }
                });
            }
        }catch(e)
        {
            logger.info("Token Confirmation Error: " + e);
            return res.status(500).send([]);
        }
    }catch(e)
    {
        logger.info(req.headers.tid + " is not authorize.");
        return res.status(500).send([]);
    }
});

function isNumber(str) {
    if (typeof str != "string") 
        return false
    return !isNaN(str) && !isNaN(parseFloat(str))
}

router.get("/superagents/getwithdrawals/:sd/:ed", function(req, res)
{
    try
    {
        var tid = req.headers.tid;
        var email = req.headers.email;
        var token = req.headers.token;
        var subtid = req.headers.subtid;
        var sd = req.params.sd;
        var ed = req.params.ed;
        try
        {
            if(tid === null || email === null || token === null
                || subtid === null || sd === null
                || ed === null)
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
                        return res.status(500).send([]);
                    }else
                    {
                        if(lol.rows === undefined || lol.rows.length !== 1)
                        {
                            logger.info("Kindly login again " + req.clientIp);
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
                                return res.status(500).send([]);
                            }else
                            {
                                if(lol.rows[0].username !== email)
                                {
                                    logger.info("Username Dont Match. " + req.clientIp);
                                    return res.status(500).send([]);
                                }else if(lol.rows[0].role !== "user" && lol.rows[0].role !== "agent"
                                    && lol.rows[0].role !== "super-agent" && lol.rows[0].role !== "ptsp")
                                {
                                    logger.info("Not a valid User. " + req.clientIp);
                                    return res.status(500).send([]);
                                }else
                                {   
                                    //CASH DEPOSIT / TRANSFER
                                    var sqry = "SELECT * FROM frometranzact WHERE transtype = $1 AND tid = $2 AND tousedate BETWEEN $3 AND $4 ORDER BY id DESC"
                                    pool.query(sqry, ["CASH WITHDRAWAL", subtid, sd, ed], (err, transaction) => {
                                        if (err) 
                                        {
                                            logger.info("tms TOKEN CHECK FAILED FOR " + req.clientIp);
                                            return res.status(500).send([]);
                                        }else
                                        {
                                            logger.info("CASHOUT EXPORTED FOR: " + req.clientIp);
                                            var amount = 0.0;
                                            var agent = 0.0;
                                            var superagent = 0.0;
                                            var ptsp = 0.0;
                                            var len = transaction.rows.length;
                                            if(len < 1)
                                            {
                                                var obj = new Object();
                                                superagent = 0.0;
                                                obj.type = "CASH WITHDRAWAL";
                                                obj.total = amount;
                                                obj.agentamount = agent;
                                                obj.superagent = superagent;
                                                obj.supersuper = ptsp;
                                                obj.tid = subtid;
                                                return res.status(200).send(obj);  
                                            }else
                                            {
                                                var inc = 0;
                                                transaction.rows.forEach(function( trans ) {
                                                    inc = inc + 1;
                                                    if(isNumber(trans.amount) === true)
                                                    {
                                                        amount = (parseFloat(amount) + parseFloat(trans.amount)).toFixed(2);    
                                                    }

                                                    if(isNumber(trans.amount) === true)
                                                    {
                                                        agent = (parseFloat(agent) + parseFloat(trans.agentamount)).toFixed(2);    
                                                    }

                                                    if(isNumber(trans.superagentamount) === true)
                                                    {
                                                        superagent = (parseFloat(superagent) + parseFloat(trans.superagentamount)).toFixed(2);    
                                                    }
                                                    if(inc === len)
                                                    {
                                                        logger.info("Spitting out Withdrawals. Ip: " + req.clientIp + "  " + new Date().toLocaleString());                                                    
                                                        var obj = new Object();
                                                        if(lol.rows[0].role === "agent")
                                                        {
                                                            superagent = 0.0;
                                                        }
                                                        obj.type = "CASH WITHDRAWAL";
                                                        obj.total = amount;
                                                        obj.agentamount = agent;
                                                        obj.superagent = superagent;
                                                        obj.supersuper = ptsp;
                                                        obj.tid = subtid;
                                                        return res.status(200).send(obj);  
                                                    }
                                                });
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    }
                });
            }
        }catch(e)
        {
            logger.info("Token Confirmation Error: " + e);
            return res.status(500).send([]);
        }
    }catch(e)
    {
        logger.info(req.headers.tid + " is not authorize.");
        return res.status(500).send([]);
    }
});

router.get("/superagents/gettransfers/:sd/:ed", function(req, res)
{
    try
    {
        var tid = req.headers.tid;
        var email = req.headers.email;
        var token = req.headers.token;
        var subtid = req.headers.subtid;
        var sd = req.params.sd;
        var ed = req.params.ed;
        try
        {
            if(tid === null || email === null || token === null
                || subtid === null || sd === null
                || ed === null)
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
                        return res.status(500).send([]);
                    }else
                    {
                        if(lol.rows === undefined || lol.rows.length !== 1)
                        {
                            logger.info("Kindly login again " + req.clientIp);
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
                                return res.status(500).send([]);
                            }else
                            {
                                if(lol.rows[0].username !== email)
                                {
                                    logger.info("Username Dont Match. " + req.clientIp);
                                    return res.status(500).send([]);
                                }else if(lol.rows[0].role !== "user" && lol.rows[0].role !== "agent"
                                    && lol.rows[0].role !== "super-agent" && lol.rows[0].role !== "ptsp")
                                {
                                    logger.info("Not a valid User. " + req.clientIp);
                                    return res.status(500).send([]);
                                }else
                                {   
                                    var sqry = "SELECT * FROM frometranzact WHERE transtype = $1 AND tid = $2 AND tousedate BETWEEN $3 AND $4 ORDER BY id DESC"
                                    pool.query(sqry, ["CASH DEPOSIT / TRANSFER", subtid, sd, ed], (err, transaction) => {
                                        if (err) 
                                        {
                                            logger.info("tms TOKEN CHECK FAILED FOR " + req.clientIp);
                                            return res.status(500).send([]);
                                        }else
                                        {
                                            logger.info("CASH DEPOSIT EXPORTED FOR: " + req.clientIp);
                                            var amount = 0.0;
                                            var agent = 0.0;
                                            var superagent = 0.0;
                                            var ptsp = 0.0;
                                            var len = transaction.rows.length;
                                            if(len < 1)
                                            {
                                                var obj = new Object();
                                                superagent = 0.0;
                                                obj.type = "TRANSFERS";
                                                obj.total = amount;
                                                obj.agentamount = agent;
                                                obj.superagent = superagent;
                                                obj.supersuper = ptsp;
                                                obj.tid = subtid;
                                                return res.status(200).send(obj);  
                                            }else
                                            {
                                                var inc = 0;
                                                transaction.rows.forEach(function( trans ) {
                                                    inc = inc + 1;
                                                    if(isNumber(trans.amount) === true)
                                                    {
                                                        amount = (parseFloat(amount) + parseFloat(trans.amount)).toFixed(2);    
                                                    }

                                                    if(isNumber(trans.amount) === true)
                                                    {
                                                        agent = 0;
                                                        //agent = (parseFloat(agent) + parseFloat(trans.agentamount)).toFixed(2);    
                                                    }

                                                    if(isNumber(trans.superagentamount) === true)
                                                    {
                                                        superagent = (parseFloat(superagent) + parseFloat(trans.superagentamount)).toFixed(2);    
                                                    }
                                                    if(inc === len)
                                                    {
                                                        logger.info("Spitting out Transfers. Ip: " + req.clientIp + "  " + new Date().toLocaleString());                                                    
                                                        var obj = new Object();
                                                        if(lol.rows[0].role === "agent")
                                                        {
                                                            superagent = 0.0;
                                                        }
                                                        obj.type = "TRANSFERS";
                                                        obj.total = amount;
                                                        obj.agentamount = agent;
                                                        obj.superagent = superagent;
                                                        obj.supersuper = ptsp;
                                                        obj.tid = subtid;
                                                        return res.status(200).send(obj);  
                                                    }
                                                });
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    }
                });
            }
        }catch(e)
        {
            logger.info("Token Confirmation Error: " + e);
            return res.status(500).send([]);
        }
    }catch(e)
    {
        logger.info(req.headers.tid + " is not authorize.");
        return res.status(500).send([]);
    }
});

router.get("/superagents/getbillsdata/:sd/:ed", function(req, res)
{
    try
    {
        var tid = req.headers.tid;
        var email = req.headers.email;
        var token = req.headers.token;
        var subtid = req.headers.subtid;
        var sd = req.params.sd;
        var ed = req.params.ed;
        try
        {
            if(tid === null || email === null || token === null
                || subtid === null || sd === null
                || ed === null)
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
                        return res.status(500).send([]);
                    }else
                    {
                        console.log("PROCEED........");
                        if(lol.rows === undefined || lol.rows.length !== 1)
                        {
                            logger.info("Kindly login again " + req.clientIp);
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
                                return res.status(500).send([]);
                            }else
                            {
                                if(lol.rows[0].username !== email)
                                {
                                    logger.info("Username Dont Match. " + req.clientIp);
                                    return res.status(500).send([]);
                                }else if(lol.rows[0].role !== "user" && lol.rows[0].role !== "agent"
                                    && lol.rows[0].role !== "super-agent" && lol.rows[0].role !== "ptsp")
                                {
                                    logger.info("Not a valid User. " + req.clientIp);
                                    return res.status(500).send([]);
                                }else
                                {   
                                    var sqry = "SELECT * FROM frometranzact WHERE transtype != $1 AND transtype != $2 AND tid = $3 AND tousedate BETWEEN $4 AND $5 ORDER BY id DESC"
                                    pool.query(sqry, ["CASH WITHDRAWAL", "CASH DEPOSIT / TRANSFER", subtid, sd, ed], (err, transaction) => {
                                        if (err) 
                                        {
                                            logger.info("tms TOKEN CHECK FAILED FOR " + req.clientIp);
                                            return res.status(500).send([]);
                                        }else
                                        {
                                            logger.info("BILLS EXPORTED FOR: " + req.clientIp);
                                            var amount = 0.0;
                                            var agent = 0.0;
                                            var superagent = 0.0;
                                            var ptsp = 0.0;
                                            var len = transaction.rows.length;
                                            if(len < 1)
                                            {
                                                var obj = new Object();
                                                superagent = 0.0;
                                                obj.type = "BILLS PAYMENT";
                                                obj.total = amount;
                                                obj.agentamount = agent;
                                                obj.superagent = superagent;
                                                obj.supersuper = ptsp;
                                                obj.tid = subtid;
                                                return res.status(200).send(obj);  
                                            }else
                                            {
                                                var inc = 0;
                                                transaction.rows.forEach(function( trans ) {
                                                    inc = inc + 1;
                                                    if(isNumber(trans.amount) === true)
                                                    {
                                                        amount = (parseFloat(amount) + parseFloat(trans.amount)).toFixed(2);    
                                                    }

                                                    if(isNumber(trans.amount) === true)
                                                    {
                                                        var settled = 0.0;
                                                        if(trans.transtype === "VTU")
                                                            settled = ((parseFloat(5) / 100) * parseFloat(trans.amount)).toFixed(2);
                                                        else if(trans.transtype === "DATA")
                                                            settled = ((parseFloat(3) / 100) * parseFloat(trans.amount)).toFixed(2);
                                                        else if(trans.transtype === "DISCO")
                                                            settled = ((parseFloat(1) / 100) * parseFloat(trans.amount)).toFixed(2);
                                                        else if(trans.transtype === "CABLE")
                                                            settled = ((parseFloat(2) / 100) * parseFloat(trans.amount)).toFixed(2);
                                                        else if(trans.transtype === "INTERNET")
                                                            settled = ((parseFloat(2) / 100) * parseFloat(trans.amount)).toFixed(2);
                                                        agent = (parseFloat(settled) + parseFloat(trans.agentamount)).toFixed(2);    
                                                    }

                                                    if(inc === len)
                                                    {
                                                        logger.info("Spitting out Bills. Ip: " + req.clientIp + "  " + new Date().toLocaleString());                                                    
                                                        var obj = new Object();
                                                        obj.type = "BILLS PAYMENT";
                                                        obj.total = amount;
                                                        obj.agentamount = agent;
                                                        obj.superagent = superagent;
                                                        obj.supersuper = ptsp;
                                                        obj.tid = subtid;
                                                        return res.status(200).send(obj);  
                                                    }
                                                });
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    }
                });
            }
        }catch(e)
        {
            logger.info("Token Confirmation Error: " + e);
            return res.status(500).send([]);
        }
    }catch(e)
    {
        logger.info(req.headers.tid + " is not authorize.");
        return res.status(500).send([]);
    }
});

router.get("/superagents/blockuser", function(req, res)
{
    try
    {
        var tid = req.headers.tid;
        var email = req.headers.email;
        var token = req.headers.token;
        var subemail = req.headers.subemail;
        try
        {
            if(tid === null || email === null || token === null
                || subemail === null)
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
                        return res.status(500).send([]);
                    }else
                    {
                        if(lol.rows === undefined || lol.rows.length !== 1)
                        {
                            logger.info("Kindly login again " + req.clientIp);
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
                                return res.status(500).send([]);
                            }else
                            {
                                var qry2 =
                                    "UPDATE tms_users SET status = $1 WHERE username = $2";
                                pool.query(qry2, ["blocked", subemail], (err, resul) => {
                                    if (err) 
                                    {
                                        console.log(err)
                                        logger.info("Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                        res.status(500).send({"status": 500, "message": "Cannot Update. Retry Later."});
                                    }else
                                    {
                                        return res.status(200).send({"status": 200, "message": "Update Successful."});
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
            return res.status(500).send([]);
        }
    }catch(e)
    {
        logger.info(req.headers.tid + " is not authorize.");
        return res.status(500).send([]);
    }
});

router.get("/superagents/unblockuser", function(req, res)
{
    try
    {
        var tid = req.headers.tid;
        var email = req.headers.email;
        var token = req.headers.token;
        var subemail = req.headers.subemail;
        try
        {
            if(tid === null || email === null || token === null
                || subemail === null)
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
                        return res.status(500).send([]);
                    }else
                    {
                        if(lol.rows === undefined || lol.rows.length !== 1)
                        {
                            logger.info("Kindly login again " + req.clientIp);
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
                                return res.status(500).send([]);
                            }else
                            {
                                var qry2 =
                                    "UPDATE tms_users SET status = $1 WHERE username = $2";
                                pool.query(qry2, ["active", subemail], (err, resul) => {
                                    if (err) 
                                    {
                                        console.log(err)
                                        logger.info("Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                        res.status(500).send({"status": 500, "message": "Cannot Update. Retry Later."});
                                    }else
                                    {
                                        return res.status(200).send({"status": 200, "message": "Update Successful."});
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
            return res.status(500).send([]);
        }
    }catch(e)
    {
        logger.info(req.headers.tid + " is not authorize.");
        return res.status(500).send([]);
    }
});

router.get("/superagents/resetdevice", function(req, res)
{
    try
    {
        var tid = req.headers.tid;
        var email = req.headers.email;
        var token = req.headers.token;
        var subemail = req.headers.subemail;
        try
        {
            if(tid === null || email === null || token === null
                || subemail === null)
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
                        return res.status(500).send([]);
                    }else
                    {
                        if(lol.rows === undefined || lol.rows.length !== 1)
                        {
                            logger.info("Kindly login again " + req.clientIp);
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
                                return res.status(500).send([]);
                            }else
                            {
                                var qry2 =
                                    "UPDATE tms_users SET phoneserialnumber = $1, mposserialnumber = $2, transferpin = $3 WHERE username = $4";
                                pool.query(qry2, ["", "", "", subemail], (err, resul) => {
                                    if (err) 
                                    {
                                        console.log(err)
                                        logger.info("Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                        res.status(500).send({"status": 500, "message": "Cannot Update. Retry Later."});
                                    }else
                                    {
                                        return res.status(200).send({"status": 200, "message": "Update Successful."});
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
            return res.status(500).send([]);
        }
    }catch(e)
    {
        logger.info(req.headers.tid + " is not authorize.");
        return res.status(500).send([]);
    }
});

function formatDt(date) {
    return date.toString().slice(0, 24);
}


router.get("/superagents/getstatement/:sd/:ed", function(req, res)
{
    try
    {
        var tid = req.headers.tid;
        var email = req.headers.email;
        var token = req.headers.token;
        var subtid = req.headers.subtid;
        var subemail = req.headers.subemail;
        var sd = req.params.sd;
        var ed = req.params.ed;   
        var root = '/root/CREDITNG';
        try
        {
            if(tid === null || email === null || token === null
                || subtid === null || subemail === null)
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
                        return res.status(500).send([]);
                    }else
                    {
                        if(lol.rows === undefined || lol.rows.length !== 1)
                        {
                            logger.info("Kindly login again " + req.clientIp);
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
                                return res.status(500).send([]);
                            }else
                            {
                                var txn = "SELECT * FROM walletactivies WHERE tousedate BETWEEN $1 AND $2 AND tid = $3 ORDER BY id DESC"
                                pool.query(txn, [sd, ed, subtid], (err, ejorn) => {
                                    if (err) 
                                    {
                                        logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                                        return res.status(500).send([]);
                                    }
                                    else
                                    {
                                        console.log("EVERYTHING IS OKAY.");
                                        res.status(200).send({"status": 200, "message": "Your statement has been sent to your Email"});
                                        
                                        console.log("EVERYTHING IS OKAY. 1");
                                        var arr = [];
                                        var tab = `<table>
                                                        <tr>
                                                            <th>AMOUNT</th>
                                                            <th>OLD AMOUNT</th>
                                                            <th>NEW AMOUNT</th>
                                                            <th>ACTION</th>
                                                            <th>INFO</th>
                                                            <th>TIME STAMP</th>
                                                        </tr>`;
                                        var dat = "";                
                                        if(ejorn.rows.length < 1)
                                        {
                                            console.log("EVERYTHING IS OKAY -1.");
                                            return;
                                        }else
                                        {
                                            console.log("EVERYTHING IS OKAY. 2");
                                            for(var i = 0; i < ejorn.rows.length; i++)
                                            {
                                                dat = dat + "<tr><td>" + ejorn.rows[i].amount + "</td>" + 
                                                    "<td>" + ejorn.rows[i].oldamount + "</td>" + 
                                                    "<td>" + ejorn.rows[i].newamount + "</td>" + 
                                                    "<td>" + ejorn.rows[i].transmode + "</td>" + 
                                                    "<td>" + ejorn.rows[i].transinfo + "</td>" + 
                                                    "<td>" + formatDt(ejorn.rows[i].timestamp) + "</td></tr>";
                                                var obj = new Object();
                                                obj.amount = ejorn.rows[i].amount;
                                                obj.oldamount = ejorn.rows[i].oldamount;
                                                obj.newamount = ejorn.rows[i].newamount;
                                                obj.transmode = ejorn.rows[i].transmode;
                                                obj.transinfo = ejorn.rows[i].transinfo;
                                                obj.timestamp = formatDt(ejorn.rows[i].timestamp);
                                                arr.push(obj);
                                            }
                                            tab = tab + dat + `</table>`;
                                            console.log(root);
                                            var lnk = path.join(root + '/public/email/downtime/impacts.html');
                                            fs.readFile(lnk, {encoding: 'utf-8'}, function (err, html) {
                                                if (err) {
                                                    console.log(err);
                                                } else {
                                                    console.log("EVERYTHING IS OKAY. 3");
                                                    const data = arr;
                                                    const fileName = 'impacts'
                                                    const exportType = 'xls'
                                                    const result = exportFromJSON({
                                                        data,
                                                        fileName,
                                                        exportType,
                                                        processor (content, type, fileName) {
                                                            return content
                                                        }
                                                    });
                                                    var filen = randomstring.generate({
                                                                    length: 12,
                                                                    charset: 'alphabetic'
                                                                });
                                                    filen = filen + ".xls";
                                                    var file = path.join(root + '/public/downloads/' + filen);
                                                    fs.writeFile(file, result, function (err) {
                                                        if (err)
                                                        {
                                                            logger.info("Error occurred while creating xls");
                                                            logger.info(err);
                                                            return;
                                                        }else
                                                        {
                                                            var template = handlebars.compile(html);
                                                            var replacements = {
                                                                headingwise: "WALLET IMPACT FOR " + subtid + ".",
                                                                email: subemail,
                                                                tid: subtid,
                                                                tab: tab
                                                            };
                                                            var htmlToSend = template(replacements);
                                                            var mailOptions = {
                                                                from: emailHeading, // sender address
                                                                replyTo: replyTo,
                                                                to: email, // list of receivers
                                                                subject: "tms WALLET RECORDS " + subtid, // Subject line
                                                                html: htmlToSend, //plain text body with html format
                                                                attachments: [
                                                                    {
                                                                        filename: filen,
                                                                        path: file
                                                                    },
                                                                    {
                                                                        filename: 'bg_1.jpg',
                                                                        path: path.join(root + '/public/email/downtime/images/bg_1.jpg'),
                                                                        cid: 'bg_1.jpg'
                                                                    },
                                                                    {
                                                                        filename: 'megaphone.png',
                                                                        path: path.join(root + '/public/email/downtime/images/megaphone.png'),
                                                                        cid: 'megaphone.png'
                                                                    },
                                                                    {
                                                                        filename: 'work.png',
                                                                        path: path.join(root + '/public/email/downtime/images/work.png'),
                                                                        cid: 'work.png'
                                                                    },
                                                                    {
                                                                        filename: 'network.png',
                                                                        path: path.join(root + '/public/email/downtime/images/network.png'),
                                                                        cid: 'network.png'
                                                                    },
                                                                    {
                                                                        filename: 'ticket.png',
                                                                        path: path.join(root + '/public/email/downtime/images/ticket.png'),
                                                                        cid: 'ticket.png'
                                                                    }
                                                                ]
                                                            };
                                                            transporter.sendMail(mailOptions, function(error, info){
                                                                if (error) {
                                                                    console.log("ERROR OCCURRED");
                                                                    console.log(error);
                                                                } else {
                                                                    console.log('Email sent: ' + info.response);
                                                                }
                                                            });
                                                        }
                                                    });
                                                }
                                            });
                                        }
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
            return res.status(500).send([]);
        }
    }catch(e)
    {
        logger.info(req.headers.tid + " is not authorize.");
        return res.status(500).send([]);
    }
});

router.get("/gettxns/emails/:sd/:ed", function(req, res)
{
    try
    {
        var email = req.headers.email;
        try
        {
            if(email === null)
            {
                var arr = [];
                res.status(200).send(arr);
            }else
            {
                var qry = "SELECT * FROM terminalconfiguration WHERE email = $1";
                pool.query(qry, [email], (err, lol) => {
                    if (err) 
                    {
                        logger.info("tms TOKEN CHECK FAILED FOR " + req.clientIp);
                        return res.status(500).send([]);
                    }else
                    {
                        if(lol.rows === undefined || lol.rows.length < 1)
                        {
                            logger.info("Kindly login again " + req.clientIp);
                            return res.status(500).send([]);
                        }else
                        {
                            var sd = req.params.sd;
                            var ed = req.params.ed;
                            var txn = "SELECT * FROM ejournal WHERE terminal_id = $1 AND current_date_uzoezi BETWEEN $2 AND $3 ORDER BY id DESC";
                            pool.query(txn, [lol.rows[0].tid, sd, ed], (err, transaction) => {
                                if (err) 
                                {
                                    logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                                    return res.status(500).send([]);
                                }
                                else
                                {
                                    console.log("SENDING BACK TXNS");
                                    res.status(200).send(transaction.rows);
                                }
                            });
                        }
                    }
                });
            }
        }catch(e)
        {
            logger.info("Token Confirmation Error: " + e);
            return res.status(500).send([]);
        }
    }catch(e)
    {
        logger.info(req.headers.tid + " is not authorize.");
        return res.status(500).send([]);
    }
});

router.get("/checkuser", function(req, res)
{
    try
    {
        var email = req.headers.email;
        try
        {
            var obj = new Object();
            if(email === null)
            {
                obj.registered = "false";
                res.status(500).send(obj);
            }else
            {
                var qry = "SELECT * FROM tms_users WHERE username = $1";
                pool.query(qry, [email], (err, lol) => {
                    if (err) 
                    {
                        logger.info("tms TOKEN CHECK FAILED FOR " + req.clientIp);
                        obj.registered = "false";
                        res.status(500).send(obj);
                    }else
                    {
                        if(lol.rows === undefined || lol.rows.length < 1)
                        {
                            logger.info("Kindly login again " + req.clientIp);
                            obj.registered = "false";
                            res.status(200).send(obj);
                        }else
                        {
                            obj.registered = "true";
                            res.status(200).send(obj);
                        }
                    }
                });
            }
        }catch(e)
        {
            logger.info("Token Confirmation Error: " + e);
            return res.status(500).send([]);
        }
    }catch(e)
    {
        logger.info(req.headers.email + " is not authorize.");
        return res.status(500).send([]);
    }
});

module.exports.router = router;