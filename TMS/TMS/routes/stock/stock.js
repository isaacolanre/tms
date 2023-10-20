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
                        return res.status(200).render("stock/stock", {details: JSON.stringify(response), role: role, usertype, usertype});
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

router.get("/getstock/:startdate/:enddate", function(req, res)
{
    console.log("Inside get all transactions");
    req.socket.setKeepAlive();
    var str = new Date().toLocaleString();
    var token = req.cookies.token_tcm;
    var username = req.cookies.username;
    var startdate = req.params.startdate;
    var enddate = req.params.enddate;
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
                    const txn = "SELECT * FROM stock WHERE tousedate BETWEEN $1 AND $2 order by id desc";
                    pool.query(txn, [startdate, enddate], (err,  comms) => {    
                        if (err) 
                        {
                            logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                            return res.status(500).send([]);
                        }
                        else
                        {
                            logger.info("All Transactions Successfully saved to " + req.clientIp + "  " + new Date().toLocaleString());
                            logger.info("Length of data: " + comms.rows.length);
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

router.get("/getallstock", function(req, res)
{
    console.log("Inside get all transactions");
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
                    const txn = "SELECT * FROM stock order by id desc";
                    pool.query(txn, (err,  comms) => {    
                        if (err) 
                        {
                            logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                            return res.status(500).send([]);
                        }
                        else
                        {
                            logger.info("All Transactions Successfully saved to " + req.clientIp + "  " + new Date().toLocaleString());
                            logger.info("ALL Length of data: " + comms.rows.length);
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

router.delete("/deletedata/:id", function(req, res)
{
    try
    {
        var id = req.params.id;
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
                        var qry2 = "DELETE FROM stock where id = $1";
                        pool.query(qry2, [id], (err, resul) => {
                            if (err) 
                            {
                                logger.info("Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                res.status(500).send({"status": 500, "message": "Others depend on this."});
                            }else
                            {
                                return res.status(200).send({"status": 200, "message": "Successful Delete."});
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
                        if(req.body.edit === 'true')
                        {
                            var qry2 =
                                "UPDATE stock SET terminalname = $1, typeofterminal = $2, manufacturer = $3, model = $4, " + 
                                "specs = $5, manufactureddate = $6, serialnumber = $7, terminalid = $8, appversion = $9, remarks = $10," + 
                                "datemodified = $11, namemodified = $12 WHERE id = $13";
                            pool.query(qry2, [req.body.terminalname, req.body.typeofterminal, req.body.manufacturer,
                                req.body.model, req.body.specs, req.body.manufactureddate,
                                req.body.serialnumber, req.body.terminalid, req.body.appversion,
                                req.body.remarks,
                                datetime(), result.rows[0].fullname, req.body.id], (err, resul) => {
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
                        }else
                        {
                            var qry2 = "INSERT INTO stock " + 
                                "(terminalname, typeofterminal, manufacturer, model, " + 
                                "specs, manufactureddate, serialnumber, terminalid, appversion, remarks," +
                                    "addedby, ifavailable, datecreated, namecreated) " + 
                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)";
                            pool.query(qry2, [req.body.terminalname, req.body.typeofterminal, req.body.manufacturer,
                                req.body.model, req.body.specs, req.body.manufactureddate,
                                req.body.serialnumber, req.body.terminalid, req.body.appversion,
                                req.body.remarks,
                                req.cookies.username, "true", datetime(), result.rows[0].fullname], (err, resul) => {
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
            }
        });
    }catch(e)
    {
        logger.info(e);
        logger.info("Having Issues with User Delete " + req.clientIp);
        res.status(500).send({"status": 500, "message": "Runtime error occurred. Try Later."});
    }
});

router.post("/batch", function(req, res)
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
                        var upload = req.files.upload;
                        var addedby = req.cookies.username;
                        var datecreated = datetime();
                        var namecreated = result.rows[0].fullname;

                        var lnk = path.join(__dirname + '/../../public/batch/' + upload.name);
			            logger.info("File Directory: " + lnk);
                        upload.mv(lnk, function(err) {
                            if(err)
                            {
				                logger.info("File Not Saved.");
                                console.log(err);
                                res.status(500).send({"status": 500, "message": "Batch Upload Not Successful."});
                            }else
                            {
                                var xlsxtojson = require("xlsx-to-json");
			                    logger.info("File Saved.");
                                xlsxtojson({
                                    input: lnk,  // input xls
                                    output: "output.json" // output json
                                }, function(err, result) {
                                    if(err) 
                                    {
					                   logger.info("Xlsx not processing.");
                                        console.log(err);
                                        res.status(500).send({"status": 500, "message": "Batch Upload Not Successful."});
                                    } else 
                                    {
					                    logger.info("Xlsx Processing.");
                                        var ejarr = JSON.parse(JSON.stringify(result));
					                    logger.info("Done with parsing");
                                        arrValue = [];
                                        val = 1;
                                        strg = "";
                                        var dele = "(";
                                        main = "(terminalname, typeofterminal, manufacturer, model, specs, manufactureddate, " + 
                                        "serialnumber, terminalid, appversion, remarks, addedby, ifavailable, datecreated, namecreated) VALUES ";
                                        for(var i = 0; i < ejarr.length; i++)
                                        {
                                            strg += "(";
                                            arrValue.push(ejarr[i].terminalname);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].typeofterminal);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].manufacturer);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].model);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].specs);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].manufactureddate);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].serialnumber);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].terminalid);
                                            strg += "$" + val.toString() + ",";
                                            dele += "terminalid = '" + ejarr[i].terminalid + "'";
                                            val++;
                                            arrValue.push(ejarr[i].appversion);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].remarks);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(req.cookies.username);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push("true");
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(datecreated);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(namecreated);
                                            strg += "$" + val.toString();
                                            val++;
                                            if(ejarr[i + 1].terminalname == "")
                                            {
                                                strg += ")";
                                                dele += ")";
                                                break;
                                            }else
                                            {
                                                strg += "),";
                                                dele += " OR ";
                                            }
                                        }
                                        var use = "INSERT INTO stock " + main + strg 
                                            + " ON CONFLICT (serialnumber) DO UPDATE SET terminalname = EXCLUDED.terminalname, typeofterminal = EXCLUDED.typeofterminal, " + 
                                            "manufacturer = EXCLUDED.manufacturer, model = EXCLUDED.model, specs = EXCLUDED.specs, " +
                                            "manufactureddate = EXCLUDED.manufactureddate, serialnumber = EXCLUDED.serialnumber, terminalid = EXCLUDED.terminalid," +
                                            "appversion = EXCLUDED.appversion, remarks = EXCLUDED.remarks"
                                            + ";";
                                        console.log(use);
                                        pool.query(use, arrValue, (err, result) => {
                                            if (err) 
                                            {
                                                logger.info("James: " + err);
                                                var fs = require('fs');
                                                fs.unlinkSync(lnk);
                                                fs.unlinkSync("output.json");
                                                res.status(500).send({"status": 500, "message": "Batch Upload Not Successful."});
                                            }
                                            else
                                            {
                                                console.log("Stock successful insert");
                                                var fs = require('fs');
                                                fs.unlinkSync(lnk);
                                                fs.unlinkSync("output.json");
                                                res.status(200).send({"status": 200, "message": "Batch Upload Successful."});
                                            }
                                        });
                                        
                                        /*var fdel = "DELETE FROM stock where " + dele;
                                        //console.log(fdel);
                                        pool.query(fdel, (err, resul) => {
                                            if (err) 
                                            {
                                                logger.info("James: " + err);
                                                var fs = require('fs');
                                                fs.unlinkSync(lnk);
                                                fs.unlinkSync("output.json");
                                                res.status(500).send({"status": 500, "message": "Batch Upload Not Successful."});
                                            }
                                            else
                                            {
                                                console.log("Successful delete");
                                                var use = "INSERT INTO stock " + main + strg 
                                                    + " ON CONFLICT (serialnumber) DO UPDATE SET terminalname = EXCLUDED.terminalname, typeofterminal = EXCLUDED.typeofterminal, " + 
                                                    "manufacturer = EXCLUDED.manufacturer, model = EXCLUDED.model, specs = EXCLUDED.specs, " +
                                                    "manufactureddate = EXCLUDED.manufactureddate, serialnumber = EXCLUDED.serialnumber, terminalid = EXCLUDED.terminalid," +
                                                    "appversion = EXCLUDED.appversion, remarks = EXCLUDED.remarks"
                                                    + ";";
                                                console.log(use);
                                                pool.query(use, arrValue, (err, result) => {
                                                    if (err) 
                                                    {
                                                        logger.info("James: " + err);
                                                        var fs = require('fs');
                                                        fs.unlinkSync(lnk);
                                                        fs.unlinkSync("output.json");
                                                        res.status(500).send({"status": 500, "message": "Batch Upload Not Successful."});
                                                    }
                                                    else
                                                    {
                                                        console.log("Stock successful insert");
                                                        var fs = require('fs');
                                                        fs.unlinkSync(lnk);
                                                        fs.unlinkSync("output.json");
                                                        res.status(200).send({"status": 200, "message": "Batch Upload Successful."});
                                                    }
                                                });
                                            }
                                        });
                                        */
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
        logger.error("Channels Logo Post could not be served to " + req.clientIp);
        res.status(500).send({"status": 500, "message": "Server Error"});
    }
});





router.get("/individual", function(req, res)
{
    try
    {
        var clientServerOptions = {
            uri: 'https://tms.ng/api/v1/dcba4321/details',
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Basic Y2FuYWFuOmtvbG9tb25pNDMyMSo='
            }
        }
        request(clientServerOptions, function (error, split) {
            if(error)
            {
                logger.info("ERROR: " + error);
                return res.header("Content-Type",'Application/json').status(500).send(split);
            }else
            {
                logger.info("SUCCESS");
                var ejarr2 = JSON.parse(split.body);
                logger.info("Done with parsing: " + ejarr2.data.length);
                //return res.header("Content-Type",'Application/json').status(200).send(ejarr);
                var respons = [];
                var ejarr = ejarr2.data;
                var inc = 0;
                var len = ejarr.length;
                ejarr.forEach(function( transaction ) {
                    var qry2 = "INSERT INTO tms_users " + 
                    "(fullname, username, addedby, role, email, status, password, " + 
                    "justset, usertype, approved, approvedby, datecreated, namecreated, bankname, tmo, phonenumber) " + 
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                    pool.query(qry2, [transaction.firstname + " " + transaction.lastname, 
                        transaction.email, "tms", "agent", transaction.email, "active", 
                        transaction.password, "true", "agent", 
                        "true", "tms", new Date().toLocaleString(), "MIGRATION DATA", "NA", "551", transaction.phone], (err, resul) => {
                        if (err) 
                        {
                            inc = inc + 1;
                            logger.info("Error Occurred: " + err);
                            respons.push(transaction);
                            if(inc === len)
                            {
                                return res.header("Content-Type",'Application/json').status(200).send(respons);
                            }
                        }else
                        {
                            logger.info("Successfully Insert");
                            if(1)
                            {
                                var qry2 = "INSERT INTO agentaccount " + 
                                    "(username, lastbalance, balance, lastmodifiedby, blocked, txnrules, typeofuser) " + 
                                    "VALUES ($1, $2, $3, $4, $5, $6, $7)";
                                pool.query(qry2, [transaction.email, "0.00", "0.00",
                                    transaction.email, "false", "1000###70???30", "agent"], (err, resul) => {
                                    if (err) 
                                    {
                                        inc = inc + 1;
                                        logger.info("2x Error Occurred: " + err);
                                        respons.push(transaction);
                                        if(inc === len)
                                        {
                                            return res.header("Content-Type",'Application/json').status(200).send(respons);
                                        }
                                    }else
                                    {
                                        inc = inc + 1;
                                        respons.push(transaction);
                                        if(inc === len)
                                        {
                                            return res.header("Content-Type",'Application/json').status(200).send(respons);
                                        }
                                    }
                                });
                            }
                        }
                    });
                });
            }
        });    
    }catch(e)
    {
        logger.info(e);
        logger.info("Having Issues with User Delete " + req.clientIp);
        res.status(500).send({"status": 500, "message": "Runtime error occurred. Try Later."});
    }
});
                            
router.get("/migrate", function(req, res)
{
    try
    {
        var clientServerOptions = {
            uri: 'https://tms.ng/api/v1/dcba4321',
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Basic Y2FuYWFuOmtvbG9tb25pNDMyMSo='
            }
        }
        request(clientServerOptions, function (error, split) {
            if(error)
            {
                logger.info("ERROR: " + error);
                return res.header("Content-Type",'Application/json').status(500).send(split);
            }else
            {
                logger.info("SUCCESS");
                var ejarr2 = JSON.parse(split.body);
                logger.info("Done with parsing: " + ejarr2.data.length);
                //return res.header("Content-Type",'Application/json').status(200).send(ejarr);

                var ejarr = ejarr2.data;
                logger.info("Done with parsing");
                arrValue = [];
                val = 1;
                strg = "";
                var dele = "(";
                main = "(terminalname, typeofterminal, manufacturer, model, specs, manufactureddate, " + 
                "serialnumber, terminalid, appversion, remarks, addedby, ifavailable, datecreated, namecreated) VALUES ";
                for(var i = 0; i < ejarr.length; i++)
                {
                    strg += "(";
                    arrValue.push("VM30");
                    strg += "$" + val.toString() + ",";
                    val++;
                    arrValue.push("MPOS");
                    strg += "$" + val.toString() + ",";
                    val++;
                    arrValue.push("AISINO");
                    strg += "$" + val.toString() + ",";
                    val++;
                    arrValue.push("VM30");
                    strg += "$" + val.toString() + ",";
                    val++;
                    arrValue.push("128mb of Rom");
                    strg += "$" + val.toString() + ",";
                    val++;
                    arrValue.push("2018-11-01");
                    strg += "$" + val.toString() + ",";
                    val++;
                    arrValue.push(ejarr[i].email);
                    strg += "$" + val.toString() + ",";
                    val++;
                    arrValue.push(ejarr[i].tid);
                    strg += "$" + val.toString() + ",";
                    dele += "terminalid = '" + ejarr[i].terminalid + "'";
                    val++;
                    arrValue.push("1.0.1");
                    strg += "$" + val.toString() + ",";
                    val++;
                    arrValue.push("OK");
                    strg += "$" + val.toString() + ",";
                    val++;
                    arrValue.push("MIGRATION");
                    strg += "$" + val.toString() + ",";
                    val++;
                    arrValue.push("true");
                    strg += "$" + val.toString() + ",";
                    val++;
                    arrValue.push("2020-10-23");
                    strg += "$" + val.toString() + ",";
                    val++;
                    arrValue.push("CANAAN MIGRATION");
                    strg += "$" + val.toString();
                    val++;

                    if((i + 1) === ejarr.length)
                    {
                        strg += ")";
                        dele += ")";
                        break;
                    }else
                    {
                        strg += "),";
                        dele += " OR ";
                    }
                }
                var use = "INSERT INTO stock " + main + strg 
                    + " ON CONFLICT (serialnumber) DO UPDATE SET terminalname = EXCLUDED.terminalname, typeofterminal = EXCLUDED.typeofterminal, " + 
                    "manufacturer = EXCLUDED.manufacturer, model = EXCLUDED.model, specs = EXCLUDED.specs, " +
                    "manufactureddate = EXCLUDED.manufactureddate, serialnumber = EXCLUDED.serialnumber, terminalid = EXCLUDED.terminalid," +
                    "appversion = EXCLUDED.appversion, remarks = EXCLUDED.remarks"
                    + ";";
                console.log(use);
                pool.query(use, arrValue, (err, result) => {
                    if (err) 
                    {
                        logger.info("James: " + err);
                        return res.status(500).send({"status": 500, "message": "Batch Upload Not Successful."});
                    }
                    else
                    {
                        console.log("Stock successful insert");
                        return res.header("Content-Type",'Application/json').status(200).send(ejarr);
                    }
                });
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