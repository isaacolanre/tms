var router = express.Router();

router.get("/getalltids", function(req, res)
{
    try
    {
        var str = new Date().toLocaleString();
        var qry2 = "SELECT * FROM terminalconfiguration where ptsp = $1 and ifavailable = $2";
        pool.query(qry2, ["ptsp_intellifin", "true"], (err, resul) => {
            if (err) 
            {
                res.status(500).send({"status": 500, "message": "Cannot Query. Retry Later."});
            }else
            {
                return res.status(200).send({"status": 200, "length": resul.rows.length, "message": resul.rows});
            }
        });
    }catch(e)
    {
        logger.info(req.cookies.username + " is not authorize to view URL 3");
        return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Authorized."});
    }
});

router.get("/transactions/:tid/:startdate/:endate", function(req, res)
{
    req.socket.setKeepAlive();
    var str = new Date().toLocaleString();
    var tid = req.params.tid.toUpperCase();
    var startdate = req.params.startdate;
    var endate = req.params.endate;
    try
    {
        var qry = "SELECT * FROM terminalconfiguration WHERE tid = $1 AND ptsp = $2";
        pool.query(qry, [tid, "ptsp_intellifin"], (err, result) => { 
            if (err) 
            {
                return res.status(500).send([]);
            }
            else
            {
                if(result.rows.length !== 1)
                {
                    return res.status(404).send({"status": 404, "length": 0, "message": "Tid does not exist"});
                }else
                {
                    if(tid == null)
                        return res.status(500).send([]);	
                    if(tid.length != 8)
                        return res.status(500).send([]);
                    
                    var format = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]+/;
                    if(format.test(tid))
                    {
                        return res.status(200).send([]);
                    }

                    const txn = "SELECT * FROM ejournal " + 
                        "WHERE terminal_id = '" + tid + "' AND " + 
                        "current_date_uzoezi >= " + "to_date('" + startdate + "','YYYY-MM-DD') AND " +
                        "current_date_uzoezi <= " + "to_date('" + endate + "','YYYY-MM-DD')";
                    pool.query(txn, (err,  comms) => {    
                        if (err) 
                        {
                            return res.status(500).send({"status": 404, "length": 0, "message": "Server Error"});
                        }
                        else
                        {
                            return res.status(200).send({"status": 200, "length": comms.rows.length, "message": comms.rows});									
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

router.get("/states/:tid/:startdate/:endate", function(req, res)
{
    req.socket.setKeepAlive();
    var str = new Date().toLocaleString();
    var tid = req.params.tid.toUpperCase();
    var startdate = req.params.startdate;
    var endate = req.params.endate;
    try
    {
        var qry = "SELECT * FROM terminalconfiguration WHERE tid = $1 AND ptsp = $2";
        pool.query(qry, [tid, "ptsp_intellifin"], (err, result) => { 
            if (err) 
            {
                return res.status(500).send([]);
            }
            else
            {
                if(result.rows.length !== 1)
                {
                    return res.status(404).send({"status": 404, "length": 0, "message": "Tid does not exist"});
                }else
                {
                    if(tid == null)
                        return res.status(500).send([]);	
                    if(tid.length != 8)
                        return res.status(500).send([]);
                    
                    var format = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]+/;
                    if(format.test(tid))
                    {
                        return res.status(200).send([]);
                    }

                    const txn = "SELECT * FROM terminal_state " + 
                        "WHERE terminal_id = '" + tid + "' AND " + 
                        "current_date_uzoezi >= " + "to_date('" + startdate + "','YYYY-MM-DD') AND " +
                        "current_date_uzoezi <= " + "to_date('" + endate + "','YYYY-MM-DD')";
                    pool.query(txn, (err,  comms) => {    
                        if (err) 
                        {
                            return res.status(500).send({"status": 404, "length": 0, "message": "Server Error"});
                        }
                        else
                        {
                            return res.status(200).send({"status": 200, "length": comms.rows.length, "message": comms.rows});									
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