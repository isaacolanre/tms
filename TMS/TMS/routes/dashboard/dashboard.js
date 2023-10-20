var router = express.Router();
var request = require('request');

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
                        logger.info("Spitting out dashboard to: " + req.clientIp + ". Time: " + new Date().toLocaleString());
                        return res.status(200).render("dashboard/index", {details: JSON.stringify(response), role: role, usertype, usertype});
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

router.get("/getsignup/count", function(req, res)
{
    console.log("Inside get all signup");
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
                    const txn = "SELECT count(*) AS exact_count FROM signup";
                    pool.query(txn, (err,  comms) => {    
                        if (err) 
                        {
                            logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                            return res.status(500).send([]);
                        }
                        else
                        {
                            logger.info("All Transactions Successfully saved to " + req.clientIp + "  " + new Date().toLocaleString());
                            //logger.info("Length of data: " + comms.rows);
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

router.get("/getwallets/balance", function(req, res)
{
    console.log("Inside get all balances");
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
                    const txn = "SELECT * from walletbalance ORDER BY ID DESC";
                    pool.query(txn, (err,  comms) => {    
                        if (err) 
                        {
                            logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                            return res.status(500).send([]);
                        }
                        else
                        {
                            logger.info("All Transactions Successfully saved to " + req.clientIp + "  " + new Date().toLocaleString());
                            //logger.info("Length of data: " + comms.rows);
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

router.get("/getkuda/balance", function(req, res)
{
    console.log("Inside get all balances");
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
                    request('http://192.46.223.163:9990/apis/etop/kuda/transfer/getadminbalance', function (error, response, body) {
                        if (!error && response.statusCode === 200) {
                            console.log(body) // Print the google web page.
                            return res.status(200).send(body);
                        }else
                        {
                            console.log("An error Occurred....: " + error);
                            return res.status(500).send([]);
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

router.get("/getitex/balance", function(req, res)
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
                    request('http://192.46.223.163:9990/apis/etop/bills/wallet/balance', function (error, response, body) {
                        if (!error && response.statusCode === 200) {
                            console.log(body) // Print the google web page.
                            return res.status(200).send(body);
                        }else
                        {
                            console.log("An error Occurred....: " + error);
                            return res.status(500).send([]);
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

router.get("/signup/recent", function(req, res)
{
    console.log("Inside get all balances");
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
                    const txn = "SELECT * from signup ORDER BY ID DESC LIMIT 10";
                    pool.query(txn, (err,  comms) => {    
                        if (err) 
                        {
                            logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                            return res.status(500).send([]);
                        }
                        else
                        {
                            logger.info("All Transactions Successfully saved to " + req.clientIp + "  " + new Date().toLocaleString());
                            //logger.info("Length of data: " + comms.rows);
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

router.get("/lastfailed/recent", function(req, res)
{
    console.log("Inside get all balances");
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
                    const txn = "SELECT * from transactions WHERE status != $1 ORDER BY ID DESC LIMIT 10";
                    pool.query(txn, ["00"], (err,  comms) => {    
                        if (err) 
                        {
                            logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                            return res.status(500).send([]);
                        }
                        else
                        {
                            logger.info("All Transactions Successfully saved to " + req.clientIp + "  " + new Date().toLocaleString());
                            //logger.info("Length of data: " + comms.rows);
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



module.exports.router = router;