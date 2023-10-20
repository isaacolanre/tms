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
                        return res.status(200).render("terminal/terminal", {details: JSON.stringify(response), role: role, usertype, usertype});
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


router.get("/getterminals/:startdate/:enddate", function(req, res)
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
                    const txn = "SELECT * FROM terminalconfiguration WHERE tousedate BETWEEN $1 AND $2 order by id desc";
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

router.get("/getallterminal", function(req, res)
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
                    const txn = "SELECT * FROM terminalconfiguration order by id desc";
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

router.delete("/deleteterminals/:id", function(req, res)
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
                        var qry2 = "DELETE FROM terminalconfiguration where id = $1";
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
                                        main = "(accountbank, accountcode, accountname, accountnumber, dialogheading, mcc, tid, mid, " + 
                                        "serialnumber, profileid, terminalmodel, initapplicationversion, merchantname, merchantaddress, " + 
                                        "adminpin, merchantpin, changepin, addedby, ifavailable, contactname, contactphone, email, datecreated, " + 
                                        "namecreated, lga, appname, country, countrycode, maker, profilename, simname, simnumber, " + 
                                        "simserial, terminalmanufacturer, blocked, blockedpin, ptsp, bankusername, bankname, ownerusername, superagent, " +
                                        "saaccountname, saaccountcode, saaccountnumber, saaccountbank, caaccountname, caaccountcode, caaccountnumber, caaccountbank, " +
                                        "tmsfeerule, superagentfeerule, tmstransferrule, superagenttransferrule, msc, switchfee, instantvalue, instantvaluetime, instantvaluepercentage, stampduty, " +
                                        "maskedpan, tmo, maxamount, sanefnumber, percentagerule, superaccountname, superaccountnumber, superaccountcode, superbankname, superpercentage, hostswitchamount, " +
                                        "vtu, data, discos, cable, internet, examination, " +  
                                        "iswtid, iswmid, wdcapped, wdsharesa, wdsharess, cttms, ctsuperagent, ctsupersuperagent, wtsupersuper, thirdhostamt, transferoption, bills, cardholdername" +
                                        ") VALUES ";
                                        
                                        
                                        for(var i = 0; i < ejarr.length; i++)
                                        {
                                            strg += "(";
                                            arrValue.push(ejarr[i].accountbank);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].accountcode);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].accountname);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].accountnumber);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].dialogheading);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].mcc);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].tid);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].mid);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].serialnumber);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].profileid);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].terminalmodel);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].initapplicationversion);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].merchantname);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].merchantaddress);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].adminpin);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].merchantpin);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].changepin);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(req.cookies.username);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push("true");
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].contactname);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].contactphone);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].email);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(datetime());
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(namecreated);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].lga);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].appname);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].country);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].countrycode);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(namecreated);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].profilename);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].simname);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].simnumber);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].simserial);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].terminalmanufacturer);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].blocked);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].blockedpin);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].ptsp);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].bankusername);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].bankname);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].ownerusername);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].superagent);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].saaccountname);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].saaccountcode);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].saaccountnumber);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].saaccountbank);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].caaccountname);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].caaccountcode);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].caaccountnumber);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].caaccountbank);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].tmsfeerule);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].superagentfeerule);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].tmstransferrule);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].superagenttransferrule);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].msc);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            arrValue.push(ejarr[i].switchfee);
                                            strg += "$" + val.toString() + ",";
                                            val++; 
                                            arrValue.push(ejarr[i].instantvalue);
                                            strg += "$" + val.toString() + ",";
                                            val++; 
                                            arrValue.push(ejarr[i].instantvaluetime);
                                            strg += "$" + val.toString() + ",";
                                            val++; 
                                            arrValue.push(ejarr[i].instantvaluepercentage);
                                            strg += "$" + val.toString() + ",";
                                            val++; 
                                            arrValue.push(ejarr[i].stampduty);
                                            strg += "$" + val.toString() + ",";
                                            val++; 
                                            
                                            arrValue.push(encryptData(ejarr[i].maskedpan, passworddb));
                                            strg += "$" + val.toString() + ",";
                                            val++;  

                                            arrValue.push(ejarr[i].tmo);
                                            strg += "$" + val.toString() + ",";
                                            val++; 

                                            arrValue.push(ejarr[i].maxamount);
                                            strg += "$" + val.toString() + ",";
                                            val++; 

                                            arrValue.push(ejarr[i].sanefnumber);
                                            strg += "$" + val.toString() + ",";
                                            val++; 

                                            arrValue.push(ejarr[i].percentagerule);
                                            strg += "$" + val.toString() + ",";
                                            val++; 

                                            //start
                                            arrValue.push(ejarr[i].superaccountname);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].superaccountnumber);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].superaccountcode);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].superbankname);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].superpercentage);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].hostswitchamount);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            //end
                                            //

                                            arrValue.push(ejarr[i].vtu);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].data);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].discos);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].cable);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].internet);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].examination);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].iswtid);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].iswmid);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].wdcapped);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].wdsharesa);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].wdsharess);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].cttms);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].ctsuperagent);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].ctsupersuperagent);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].wtsupersuper);
                                            strg += "$" + val.toString() + ",";
                                            val++;
                                            
                                            arrValue.push(ejarr[i].thirdhostamt);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].transferoption);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(ejarr[i].bills);
                                            strg += "$" + val.toString() + ",";
                                            val++;

                                            arrValue.push(encryptData(ejarr[i].cardholdername, passworddb));
                                            strg += "$" + val.toString();
                                            val++;  

                                            if(ejarr[i + 1].tid == "")
                                            {
                                                strg += ")";
                                                break;
                                            }else
                                            {
                                                strg += "),";
                                            }
                                        }
                                        var use = "INSERT INTO terminalconfiguration " + main + strg 
                                            + " ON CONFLICT (tid) DO UPDATE SET accountbank = EXCLUDED.accountbank, accountcode = EXCLUDED.accountcode, " + 
                                            "accountname = EXCLUDED.accountname, accountnumber = EXCLUDED.accountnumber, dialogheading = EXCLUDED.dialogheading, " +
                                            "mcc = EXCLUDED.mcc, mid = EXCLUDED.mid, serialnumber = EXCLUDED.serialnumber," +
                                            "profileid = EXCLUDED.profileid, terminalmodel = EXCLUDED.terminalmodel, initapplicationversion = EXCLUDED.initapplicationversion, " +
                                            "merchantname = EXCLUDED.merchantname, merchantaddress = EXCLUDED.merchantaddress, adminpin = EXCLUDED.adminpin, " +
                                            "merchantpin = EXCLUDED.merchantpin, changepin = EXCLUDED.changepin, contactname = EXCLUDED.contactname, " +
                                            "contactphone = EXCLUDED.contactphone, email = EXCLUDED.email, " +
                                            "lga = EXCLUDED.lga, appname = EXCLUDED.appname, country = EXCLUDED.country, " +
                                            "countrycode = EXCLUDED.countrycode, profilename = EXCLUDED.profilename, simname = EXCLUDED.simname, " +
                                            "simnumber = EXCLUDED.simnumber, simserial = EXCLUDED.simserial, terminalmanufacturer = EXCLUDED.terminalmanufacturer, " +
                                            "blocked = EXCLUDED.blocked, blockedpin = EXCLUDED.blockedpin, ownerusername = EXCLUDED.ownerusername, " +
                                            "superagent = EXCLUDED.superagent, ptsp = EXCLUDED.ptsp, bankname = EXCLUDED.bankname, bankusername = EXCLUDED.bankusername," + 
                                            "maker = EXCLUDED.maker, ifavailable = EXCLUDED.ifavailable, addedby = EXCLUDED.addedby, namemodified = EXCLUDED.namemodified, datemodified = EXCLUDED.datemodified, " +
                                            "saaccountname = EXCLUDED.saaccountname, saaccountcode = EXCLUDED.saaccountcode, saaccountnumber = EXCLUDED.saaccountnumber, saaccountbank = EXCLUDED.saaccountbank, " +
                                            "caaccountname = EXCLUDED.caaccountname, caaccountcode = EXCLUDED.caaccountcode, caaccountnumber = EXCLUDED.caaccountnumber, caaccountbank = EXCLUDED.caaccountbank, " +
                                            "tmsfeerule = EXCLUDED.tmsfeerule, superagentfeerule = EXCLUDED.superagentfeerule, superagenttransferrule = EXCLUDED.superagenttransferrule, " + 
                                            "tmo = EXCLUDED.tmo, maxamount = EXCLUDED.maxamount, sanefnumber = EXCLUDED.sanefnumber, percentagerule = EXCLUDED.percentagerule, tmstransferrule = EXCLUDED.tmstransferrule, msc = EXCLUDED.msc, switchfee = EXCLUDED.switchfee, instantvalue = EXCLUDED.instantvalue, instantvaluetime = EXCLUDED.instantvaluetime, instantvaluepercentage = EXCLUDED.instantvaluepercentage, stampduty = EXCLUDED.stampduty, maskedpan = EXCLUDED.maskedpan, superaccountname = EXCLUDED.superaccountname, superaccountnumber = EXCLUDED.superaccountnumber, superaccountcode = EXCLUDED.superaccountcode, superbankname = EXCLUDED.superbankname, superpercentage = EXCLUDED.superpercentage, hostswitchamount = EXCLUDED.hostswitchamount, " + 
                                            "vtu = EXCLUDED.vtu, data = EXCLUDED.data, discos = EXCLUDED.discos, cable = EXCLUDED.cable, internet = EXCLUDED.internet, examination = EXCLUDED.examination, " + 
                                            "iswtid = EXCLUDED.iswtid, iswmid = EXCLUDED.iswmid, wdcapped = EXCLUDED.wdcapped, wdsharesa = EXCLUDED.wdsharesa, wdsharess = EXCLUDED.wdsharess, cttms = EXCLUDED.cttms, ctsuperagent = EXCLUDED.ctsuperagent, ctsupersuperagent = EXCLUDED.ctsupersuperagent, wtsupersuper = EXCLUDED.wtsupersuper, thirdhostamt = EXCLUDED.thirdhostamt, transferoption = EXCLUDED.transferoption, bills = EXCLUDED.bills, cardholdername = EXCLUDED.cardholdername"
                                            + ";";
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
                                                var fs = require('fs');
                                                fs.unlinkSync(lnk);
                                                fs.unlinkSync("output.json");
                                                res.status(200).send({"status": 200, "message": "Batch Upload Successful."});
                                            }
                                        });
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
                        var qry2 =
                            "UPDATE terminalconfiguration SET adminpin = $1, changepin = $2, merchantpin = $3, " + 
                            "merchantname = $4, merchantaddress = $5, blocked = $6, blockedpin = $7, ownerusername = $8, ifavailable = $9," + 
                            "datemodified = $10, namemodified = $11, profileid = $12, profilename = $13, superagent = $14, serialnumber = $15 WHERE tid = $16";
                        pool.query(qry2, [req.body.adminpin, req.body.changepin, req.body.merchantpin,
                            req.body.merchantname, req.body.merchantaddress, req.body.blocked,
                            req.body.blockedpin, req.body.ownerusername, "true",
                            datetime(), result.rows[0].fullname, req.body.profileid, req.body.profilename, req.body.superagent, req.body.serialnumber, req.body.tid], (err, resul) => {
                            if (err) 
                            {
                                console.log(err)
                                logger.info("Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                res.status(500).send({"status": 500, "message": "Cannot Update. Retry Later."});
                            }else
                            {
                                if(req.body.freeserial === "true")
                                {
                                    var serial = randomstring.generate({
                                        length: 11,
                                        charset: 'numeric'
                                    });
                                    serial = serial + "OLD" + req.body.serialnumber;
                                    var qry2 =
                                        "UPDATE signup SET serialnumber = $1, approved = $2, approvedby = $3" + 
                                        " WHERE serialnumber = $4";
                                    pool.query(qry2, [serial, "", "", req.body.serialnumber], (err, resul) => {
                                        if (err) 
                                        {
                                            console.log(err)
                                            logger.info("Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                            return res.status(200).send({"status": 200, "message": "Update Successful."});
                                        }else
                                        {
                                            return res.status(200).send({"status": 200, "message": "Update Successful."});
                                        }
                                    });
                                }else{
                                    return res.status(200).send({"status": 200, "message": "Update Successful."});
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
        logger.info("Having Issues with User Delete " + req.clientIp);
        res.status(500).send({"status": 500, "message": "Runtime error occurred. Try Later."});
    }
});


module.exports.router = router;