var router = express.Router();
var request = require('request').defaults({ rejectUnauthorized: false });

var hash = "25737df5fb669f1e8544a8b822808c2aff577e3311de2cdccbc205ac89986877";
var url = "https://shagopayments.com/api/live/b2b";

function isNumber(str) {
    if (typeof str != "string") 
        return false
    return !isNaN(str) && !isNaN(parseFloat(str))
}

router.get("/manualreversal", function(req, res) 
{
    console.log("MANUAL REVERSAL REQUEST");
    var tid = req.headers.tid;
    var amount = req.headers.amount;
    var qry = "SELECT * FROM walletbalance WHERE tid = $1";
    pool.query(qry, [tid], (err, love) => { 
        if (err) 
        {
            logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
            res.status(500).send({"status": 500, "message": "Transaction Failed."});
        }
        else
        {
            if(love.rows === undefined || love.rows.length == 0)
            {
                logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                return res.status(500).send({"status": 500, "message": "No Funds Available"});
            }else
            {
                var totAgentAmount = (parseFloat(love.rows[0].amount) + parseFloat(amount)).toFixed(2);
                var qry2 =
                    "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                pool.query(qry2, [totAgentAmount, tid], (err, resul) => {
                    if (err) 
                    {
                        console.log(err);
                        return res.status(500).send({"status": 500, "message": "An Error Occurred..."});
                    }else
                    {
                        var preBal = 0.00;
                        var newBal = 0.00;
                        preBal = love.rows[0].amount;
                        newBal = parseFloat(totAgentAmount);
                        var waA = "INSERT INTO walletactivies " + 
                            "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                            "VALUES ($1, $2, $3, $4, $5, $6)";
                        pool.query(waA, [tid, amount, preBal, newBal, 
                            "CREDIT", "MANUAL REVERSAL"], (err, resul) => {
                            if (err) 
                            {
                                logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                            }else
                            {
                                return res.status(200).send({"status": 200, "message": "Wallet Topup Successful."});
                            }
                        });
                    }
                });
            }
        }
    });
});

router.get("/debitwallet", function(req, res) 
{
    console.log("MANUAL DEBIT REQUEST");
    var tid = req.headers.tid;
    var amount = req.headers.amount;
    var qry = "SELECT * FROM walletbalance WHERE tid = $1";
    pool.query(qry, [tid], (err, love) => { 
        if (err) 
        {
            logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
            res.status(500).send({"status": 500, "message": "Transaction Failed."});
        }
        else
        {
            if(love.rows === undefined || love.rows.length == 0)
            {
                logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                return res.status(500).send({"status": 500, "message": "No Funds Available"});
            }else
            {
                var totAgentAmount = (parseFloat(love.rows[0].amount) - parseFloat(amount)).toFixed(2);
                var qry2 =
                    "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                pool.query(qry2, [totAgentAmount, tid], (err, resul) => {
                    if (err) 
                    {
                        console.log(err);
                        return res.status(500).send({"status": 500, "message": "An Error Occurred..."});
                    }else
                    {
                        var preBal = 0.00;
                        var newBal = 0.00;
                        preBal = love.rows[0].amount;
                        newBal = parseFloat(totAgentAmount);
                        var waA = "INSERT INTO walletactivies " + 
                            "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                            "VALUES ($1, $2, $3, $4, $5, $6)";
                        pool.query(waA, [tid, amount, preBal, newBal, 
                            "DEBIT", "MANUAL DEBIT"], (err, resul) => {
                            if (err) 
                            {
                                logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                            }else
                            {
                                return res.status(200).send({"status": 200, "message": "Wallet Topup Successful."});
                            }
                        });
                    }
                });
            }
        }
    });
});


router.post("/changetid", function(req, res) 
{
    console.log("CHANGING TID");
    var response = req.body;
    response.forEach(function( details ) {
        console.log("ABOUT OLD TId: " + details.tid + ". NEW TID: " + details.newtid);
        var qry2 =
            "UPDATE terminalconfiguration SET tid = $1 WHERE tid = $2";
        pool.query(qry2, [details.newtid, details.tid], (err, resul) => {
            if (err) 
            {
                console.log("1 ERROR: " + details.tid + ". NEW TID: " + details.newtid);
                console.log(err);
                return;
            }else
            {
                var qry2 =
                    "UPDATE stock SET terminalid = $1 WHERE terminalid = $2";
                pool.query(qry2, [details.newtid, details.tid], (err, resul) => {
                    if (err) 
                    {
                        console.log("2 ERROR: " + details.tid + ". NEW TID: " + details.newtid);
                        console.log(err);
                        return;
                    }else
                    {
                        var qry2 =
                            "UPDATE walletactivies SET tid = $1 WHERE tid = $2";
                        pool.query(qry2, [details.newtid, details.tid], (err, resul) => {
                            if (err) 
                            {
                                console.log("3 ERROR: " + details.tid + ". NEW TID: " + details.newtid);
                                console.log(err);
                                return;
                            }else
                            {
                                var qry2 =
                                    "UPDATE walletbalance SET tid = $1 WHERE tid = $2";
                                pool.query(qry2, [details.newtid, details.tid], (err, resul) => {
                                    if (err) 
                                    {
                                        console.log("4 ERROR: " + details.tid + ". NEW TID: " + details.newtid);
                                        console.log(err);
                                        return;
                                    }else
                                    {
                                        var qry2 =
                                            "UPDATE frometranzact SET tid = $1 WHERE tid = $2";
                                        pool.query(qry2, [details.newtid, details.tid], (err, resul) => {
                                            if (err) 
                                            {
                                                console.log("5 ERROR: " + details.tid + ". NEW TID: " + details.newtid);
                                                console.log(err);
                                                return;
                                            }else
                                            {
                                                var qry2 =
                                                    "UPDATE etranzactstatus SET tid = $1 WHERE tid = $2";
                                                pool.query(qry2, [details.newtid, details.tid], (err, resul) => {
                                                    if (err) 
                                                    {
                                                        console.log("6 ERROR: " + details.tid + ". NEW TID: " + details.newtid);
                                                        console.log(err);
                                                        return;
                                                    }else
                                                    {
                                                        var qry2 =
                                                            "UPDATE agencyinstant SET tid = $1 WHERE tid = $2";
                                                        pool.query(qry2, [details.newtid, details.tid], (err, resul) => {
                                                            if (err) 
                                                            {
                                                                console.log("7 ERROR: " + details.tid + ". NEW TID: " + details.newtid);
                                                                console.log(err);
                                                                return;
                                                            }else
                                                            {
                                                                var qry2 =
                                                                    "UPDATE ejournal SET terminal_id = $1 WHERE terminal_id = $2";
                                                                pool.query(qry2, [details.newtid, details.tid], (err, resul) => {
                                                                    if (err) 
                                                                    {
                                                                        console.log("8 ERROR: " + details.tid + ". NEW TID: " + details.newtid);
                                                                        console.log(err);
                                                                        return;
                                                                    }else
                                                                    {
                                                                        console.log("DONE CHANGING OLD TId: " + details.tid + ". NEW TID: " + details.newtid);
                                                                        return;
                                                                    }
                                                                });
                                                            }
                                                        });
                                                    }
                                                });
                                            }
                                        });
                                    }
                                });
                            }
                        });
                    }
                });
            }
        });
    });
});

router.get("/synckeys", function(req, res) 
{
    console.log("MANUAL SYNC REQUEST");
    var tid = req.headers.tid;
    var qry = "SELECT * FROM terminalconfiguration WHERE tid = $1";
    pool.query(qry, [tid], (err, result) => {
        if (err) 
        {
            logger.info("Database connection error: " + err + ". Time: " +  new Date().toLocaleString());
            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "FAILED"});
        }
        else
        {
            if(result.rows.length < 1)
            {
                logger.info("NO TID TO UPDATE. Time: " +  new Date().toLocaleString());
                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "FAILED"});
            }else
            {
                result.rows.forEach(function( terminal ) {
                    const pro =
                        "SELECT * FROM profile WHERE id = $1";
                    pool.query(pro, [terminal.profileid], (err,  profile) => { 
                        if (err) 
                        {
                            logger.info("PROFILE ID DOES NOT EXIST:" + terminal.profileid + ". Time: " +  new Date().toLocaleString());
                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "FAILED"});
                        }
                        else
                        {
                            if(profile.rows.length < 1)
                            {
                                logger.info("PROFILE ID ERROR:" + terminal.profileid + ". Time: " +  new Date().toLocaleString());
                                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "FAILED"});
                            }else
                            {
                                const sk =
                                    "SELECT * FROM keys WHERE id = $1";
                                pool.query(sk, [profile.rows[0].switchkeyid], (err,  swk) => { 
                                    if (err) 
                                    {
                                        logger.info("SWITCHKEY ID DOES NOT EXIST:" + profile.rows[0].switchkeyid + ". Time: " +  new Date().toLocaleString());
                                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "FAILED"});
                                    }
                                    else
                                    {
                                        if(swk.rows.length < 1)
                                        {
                                            logger.info("SWITCHKEY ID DOES NOT EXIST ERROR:" + profile.rows[0].switchkeyid + ". Time: " +  new Date().toLocaleString());
                                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "FAILED"});
                                        }else
                                        {
                                            const hi =
                                                "SELECT * FROM host WHERE id = $1";
                                            pool.query(hi, [profile.rows[0].hostid], (err,  hostid) => { 
                                                if (err) 
                                                {
                                                    logger.info("HOST ID DOES NOT EXIST:" + profile.rows[0].switchkeyid + ". Time: " +  new Date().toLocaleString());
                                                    return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "FAILED"});
                                                }
                                                else
                                                {
                                                    if(hostid.rows.length < 1)
                                                    {
                                                        logger.info("HOST ID DOES NOT EXIST ERROR:" + profile.rows[0].switchkeyid + ". Time: " +  new Date().toLocaleString());
                                                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "FAILED"});
                                                    }else
                                                    {
                                                        var sendout = new Object();
                                                        sendout.tid = terminal.tid;
                                                        sendout.component = swk.rows[0].component1;
                                                        sendout.ip = hostid.rows[0].ip;
                                                        sendout.port = hostid.rows[0].port;
                                                        sendout.ssl = hostid.rows[0].ssl;

                                                        var msk = JSON.stringify(sendout);
                                                        console.log(msk);

                                                        var client = new net.Socket();
                                                        client.connect(9002, 'localhost', function() {
                                                            console.log('Server Connected');
                                                            client.write(msk);
                                                            client.destroy();
                                                            return res.header("Content-Type",'application/json').status(200).send({"status": 200, "message": "SUCCESS"});
                                                        });

                                                        client.on('data', function(data) {
                                                            console.log('Response: ' + data);
                                                        });

                                                        client.on('close', function() {
                                                            console.log('Connection closed');
                                                        });
                                                    }
                                                }
                                            });
                                        }
                                    }
                                });
                            }
                        }
                    });
                });
            }
        }
    });
});

//SYNC KEYS.
router.post("/getkeys", function(req, res) 
{
    console.log("KEYS UPDATE");
    console.log(req.body);
    var response = req.body;
    
    const query5 =
        "UPDATE terminalconfiguration SET encmstkey = $1, clrmstkey = $2, encseskey = $3, clrseskey = $4, " + 
        "encpinkey = $5, clrpinkey = $6, paramdownload = $7, syncip = $8, syncport = $9 WHERE tid = $10";
    pool.query(query5, [response.encmasterkey, response.clrmasterkey, response.encsesskey, response.clrsesskey,
        response.encpinkey, response.clrpinkey, response.paramdownload, 
        response.ip, response.port, response.tid], (err,  results) => 
    {    
        if (err) 
        {
            console.log(err);
            return res.status(200).send({"status": 200, "message": "UPDATE FAILED."});
        }
        else
        {
            return res.status(200).send({"status": 200, "message": "UPDATE SUCCESS."});
        }
    });
});

//POPULATE SUPER AGENTS
router.post("/superagents", function(req, res) 
{
    console.log("Inside populate superagents and aggregators");
    var rResponse = req.body;
    var ejarr = rResponse.data;
    var len = ejarr.length;
    ejarr.forEach(function( ejarr ) {
        console.log(ejarr.tid);
        console.log(ejarr.email);
        console.log(ejarr.agents.length);
        var qry2 =
            "UPDATE tms_users SET role = $1, usertype = $2 WHERE username = $3";
        pool.query(qry2, ["super-agent", "superagent", ejarr.email], (err, resul) => {
            if (err) 
            {
                console.log(err);
                return;
            }else
            {
                console.log(ejarr.email + "SUCCESSFUL");
                return;
            }
        });
    });
    /*console.log("Inside populate superagents and aggregators");
    //var rResponse = JSON.parse(req.body);
    var rResponse = req.body;
    var ejarr = rResponse.data;
    var len = ejarr.length;
    var count = 0;
    ejarr.forEach(function( ejarr ) {
        count = count + 1;
        console.log(ejarr.tid);
        console.log(ejarr.email);
        console.log(ejarr.agents);
        console.log(ejarr.agents.length);
        //var agents = JSON.parse(ejarr.agents);
        var agents = ejarr.agents;
        var lv = 0;
        var mv = ejarr.agents.length;
        agents.forEach(function( agents ) {
            lv = lv + 1;
            var qry2 =
                "UPDATE terminalconfiguration SET superagent = $1, ptsp = $2 WHERE tid = $3";
            pool.query(qry2, [ejarr.email, ejarr.email, agents.terminal_id], (err, resul) => {
                if (err) 
                {
                    console.log("LENGTH: " + len + ". Count: " + count + ". INT LEN: " + mv
                        + "CURRENT INT LEN: " + lv);
                    console.log(err);
                    return;
                }else
                {
                    console.log("LENGTH: " + len + ". Count: " + count + ". INT LEN: " + mv
                        + "CURRENT INT LEN: " + lv);
                    return;
                }
            });
        });
    });*/
});



//POPULATE AGENTS
router.get("/populateagents", function(req, res) 
{
    console.log("Inside populate agents");
    var clientServerOptions = {
        uri: 'https://tms.ng/api/v1/dcba4321/details',
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Basic Y2FuYWFuOmtvbG9tb25pNDMyMSo='
        }
    }
    request(clientServerOptions, function (error, response) {
        if(error)
        {
            logger.info("ERROR: " + error);
            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Kolomini Failed. Retry Later"});
        }else
        {
            console.log(response.body);
            var rResponse = JSON.parse(response.body);
            var ejarr = rResponse.data;
            var len = ejarr.length;
            var count = 0;
            ejarr.forEach(function( ejarr ) {
                var qry2 = "INSERT INTO tms_users " + 
                "(fullname, username, addedby, role, email, status, password, " + 
                "justset, usertype, approved, approvedby, datecreated, namecreated, bankname, tmo, phonenumber) " + 
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                pool.query(qry2, [ejarr.firstname + " " + ejarr.lastname, ejarr.email, "ANGELA IJI", 
                    "agent", ejarr.email, "active", 
                    ejarr.password, "true", "agent", 
                    "true", "tms", new Date().toLocaleString(), "ANGELA IJI", 
                    "NA", "551", ejarr.phone], (err, resul) => {
                    if (err) 
                    {
                        logger.info(err);
                        logger.info("Database Issue.");
                        count = count + 1;
                        console.log(count + " COUNT");
                        console.log(len + " TOTAL");
                    }else
                    {
                        count = count + 1;
                        console.log(count + " COUNT");
                        console.log(len + " TOTAL");
                        if(len === count)
                            return res.status(200).send({"status": 200, "message": "Successful Signup."});
                    }
                });
            });
        }
    });
});

//POPULATE tids
router.get("/populatetid", function(req, res) 
{
    console.log("Inside populate tid");
    var clientServerOptions = {
        uri: 'https://tms.ng/api/v1/dcba4321/details',
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Basic Y2FuYWFuOmtvbG9tb25pNDMyMSo='
        }
    }
    request(clientServerOptions, function (error, response) {
        if(error)
        {
            logger.info("ERROR: " + error);
            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Kolomini Failed. Retry Later"});
        }else
        {
            console.log(response.body);
            var rResponse = JSON.parse(response.body);
            var ejarr = rResponse.data;
            var len = ejarr.length;
            var count = 0;
            ejarr.forEach(function( ejarr ) {
                var namecreated = "ANGELA IJI";
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
                "iswtid, iswmid, wdcapped, wdsharesa, wdsharess, cttms, ctsuperagent, ctsupersuperagent, wtsupersuper, cardholdername" +
                ") VALUES ";
                var tdel = "";
                
                strg += "(";
                arrValue.push("GTBANK");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("044150291");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("ANGELA IJI OGWA");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("0218779412");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("tms");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("4900");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push(ejarr.tid);
                strg += "$" + val.toString() + ",";
                val++;
                tdel = ejarr.tid;
                arrValue.push("2082OY007356966");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push(ejarr.email);
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("1");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("VM30");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("1.0.1");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push(ejarr.firstname + " " + ejarr.lastname);
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("tms INVESTMENTOY           LANG");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("1234");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("1234");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("false");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("ANGELA IJI");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("true");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push(ejarr.firstname + " " + ejarr.lastname);
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push(ejarr.phone);
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push(ejarr.email);
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push(datetime());
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push(namecreated);
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("OYO");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("tms APP");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("NIGERIA");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("566");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push(namecreated);
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("BIZZDESKGROUP");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("NA");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("NA");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("NA");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("AISINO");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("false");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("0000");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("bizzdeskgroup");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("keystone");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("KEYSTONE BANK");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push(ejarr.email);
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("");
                strg += "$" + val.toString() + ",";
                val++;

                arrValue.push("tms INV LIMITED");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("033152048");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("1007358176");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("KEYSTONE BANK");
                strg += "$" + val.toString() + ",";
                val++;

                arrValue.push("tms INV LIMITED");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("033152048");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("1007358176");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("KEYSTONE BANK");
                strg += "$" + val.toString() + ",";
                val++;

                arrValue.push("1-4999=0.30###5000-9999=0.30###10000-19999=0.30###20000-1000000=0.30###");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("1-1000000=0.20###");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("1-5000=29.00###5001-50000=28.00###50001-500000=27.00###");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("1-5000=1.00###5001-50000=2.00###50001-500000=3.00###");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("0.5");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("13");
                strg += "$" + val.toString() + ",";
                val++; 
                arrValue.push("NA");
                strg += "$" + val.toString() + ",";
                val++; 
                arrValue.push("3600");
                strg += "$" + val.toString() + ",";
                val++; 
                arrValue.push("1");
                strg += "$" + val.toString() + ",";
                val++; 
                arrValue.push("50.00");
                strg += "$" + val.toString() + ",";
                val++; 
                
                arrValue.push("NA");
                strg += "$" + val.toString() + ",";
                val++;  

                arrValue.push("551");
                strg += "$" + val.toString() + ",";
                val++; 

                arrValue.push("150000");
                strg += "$" + val.toString() + ",";
                val++; 

                arrValue.push("abc12345");
                strg += "$" + val.toString() + ",";
                val++; 

                arrValue.push("true");
                strg += "$" + val.toString() + ",";
                val++; 

                //start
                arrValue.push("tms INV LIMITED");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("1007358176");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("033152048");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("KEYSTONE BANK");
                strg += "$" + val.toString() + ",";
                val++;

                arrValue.push("1-4999=0.00###5000-9999=0.00###10000-19999=0.00###20000-1000000=0.00###");
                strg += "$" + val.toString() + ",";
                val++;

                arrValue.push("1999");
                strg += "$" + val.toString() + ",";
                val++;
                //end

                arrValue.push("1");
                strg += "$" + val.toString() + ",";
                val++;

                arrValue.push("1");
                strg += "$" + val.toString() + ",";
                val++;

                arrValue.push("1");
                strg += "$" + val.toString() + ",";
                val++;

                arrValue.push("1");
                strg += "$" + val.toString() + ",";
                val++;

                arrValue.push("2.5");
                strg += "$" + val.toString() + ",";
                val++;

                arrValue.push("1");
                strg += "$" + val.toString() + ",";
                val++;
                
                arrValue.push("2082LC17");
                strg += "$" + val.toString() + ",";
                val++;

                arrValue.push("2082OY007356966");
                strg += "$" + val.toString() + ",";
                val++;

                arrValue.push("100");
                strg += "$" + val.toString() + ",";
                val++;

                arrValue.push("0");
                strg += "$" + val.toString() + ",";
                val++;

                arrValue.push("0");
                strg += "$" + val.toString() + ",";
                val++;

                arrValue.push("100");
                strg += "$" + val.toString() + ",";
                val++;

                arrValue.push("0");
                strg += "$" + val.toString() + ",";
                val++;

                arrValue.push("0");
                strg += "$" + val.toString() + ",";
                val++;

                arrValue.push("1-5000=0.00###5001-50000=0.00###50001-500000=0.00###");
                strg += "$" + val.toString() + ",";
                val++;
                
                arrValue.push("NA");
                strg += "$" + val.toString();
                val++;  

                strg += ")";

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
                    "tmo = EXCLUDED.tmo, maxamount = EXCLUDED.maxamount, sanefnumber = EXCLUDED.sanefnumber, percentagerule = EXCLUDED.percentagerule, tmstransferrule = EXCLUDED.tmstransferrule, msc = EXCLUDED.msc, switchfee = EXCLUDED.switchfee, instantvalue = EXCLUDED.instantvalue, instantvaluetime = EXCLUDED.instantvaluetime, instantvaluepercentage = EXCLUDED.instantvaluepercentage, stampduty = EXCLUDED.stampduty, maskedpan = EXCLUDED.maskedpan, " + 
                    "superaccountname = EXCLUDED.superaccountname, superaccountnumber = EXCLUDED.superaccountnumber, superaccountcode = EXCLUDED.superaccountcode, superbankname = EXCLUDED.superbankname, superpercentage = EXCLUDED.superpercentage, hostswitchamount = EXCLUDED.hostswitchamount, " + 
                    "vtu = EXCLUDED.vtu, data = EXCLUDED.data, discos = EXCLUDED.discos, cable = EXCLUDED.cable, internet = EXCLUDED.internet, examination = EXCLUDED.examination, " + 
                    "iswtid = EXCLUDED.iswtid, iswmid = EXCLUDED.iswmid, wdcapped = EXCLUDED.wdcapped, wdsharesa = EXCLUDED.wdsharesa, wdsharess = EXCLUDED.wdsharess, cttms = EXCLUDED.cttms, ctsuperagent = EXCLUDED.ctsuperagent, ctsupersuperagent = EXCLUDED.ctsupersuperagent, wtsupersuper = EXCLUDED.wtsupersuper, cardholdername = EXCLUDED.cardholdername"
                    + ";";
                pool.query(use, arrValue, (err, result) => {
                    if (err) 
                    {
                        logger.info("James: " + err);
                        res.status(500).send({"status": 500, "message": "Approval Not Successful."});
                    }
                    else
                    {
                        count = count + 1;
                        //console.log(ejarr.tid + " SAVED");
                        //console.log(ejarr.email + " SAVED");
                        console.log(count + " COUNT");
                        console.log(len + " TOTAL");
                        if(len === count)
                            return res.header("Content-Type",'Application/json').status(200).send(rResponse.data); 
                    }
                });

            });
        }
    });
});

//POPULATE stock
router.get("/populatestock", function(req, res) 
{
    console.log("Inside populate stock");
    var clientServerOptions = {
        uri: 'https://tms.ng/api/v1/dcba4321/details',
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Basic Y2FuYWFuOmtvbG9tb25pNDMyMSo='
        }
    }
    request(clientServerOptions, function (error, response) {
        if(error)
        {
            logger.info("ERROR: " + error);
            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Kolomini Failed. Retry Later"});
        }else
        {
            console.log(response.body);
            var rResponse = JSON.parse(response.body);
            var ejarr = rResponse.data;
            var len = ejarr.length;
            var count = 0;
            ejarr.forEach(function( ejarr ) {
                var namecreated = "ANGELA IJI";
                logger.info("Done with parsing");
                arrValue = [];
                val = 1;
                strg = "";
                var dele = "(";
                main = "(terminalname, typeofterminal, manufacturer, model, specs, manufactureddate, " + 
                "serialnumber, terminalid, appversion, remarks, addedby, ifavailable, datecreated, namecreated) VALUES ";
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
                arrValue.push("128MB OF RAM");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("2020-12-02");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push(ejarr.email);
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push(ejarr.tid);
                strg += "$" + val.toString() + ",";
                dele += "terminalid = '" + ejarr.tid + "'";
                val++;
                arrValue.push("1.0.1");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("MIGRATED");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("hangelahstorm@gmail.com");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("true");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("2020-12-02");
                strg += "$" + val.toString() + ",";
                val++;
                arrValue.push("ANGELA IJI");
                strg += "$" + val.toString();
                val++;
                
                strg += ")";
                dele += ")";

                
                var use = "INSERT INTO stock " + main + strg 
                    + " ON CONFLICT (serialnumber) DO UPDATE SET terminalname = EXCLUDED.terminalname, typeofterminal = EXCLUDED.typeofterminal, " + 
                    "manufacturer = EXCLUDED.manufacturer, model = EXCLUDED.model, specs = EXCLUDED.specs, " +
                    "manufactureddate = EXCLUDED.manufactureddate, serialnumber = EXCLUDED.serialnumber, terminalid = EXCLUDED.terminalid," +
                    "appversion = EXCLUDED.appversion, remarks = EXCLUDED.remarks"
                    + ";";
                pool.query(use, arrValue, (err, result) => {
                    if (err) 
                    {
                        logger.info("James: " + err);
                        res.status(500).send({"status": 500, "message": "Batch Upload Not Successful."});
                    }
                    else
                    {
                        console.log("Stock successful insert");
                        count = count + 1;
                        console.log(count + " COUNT");
                        console.log(len + " TOTAL");
                        if(len === count)
                            res.status(200).send({"status": 200, "message": "Batch Upload Successful."});
                    }
                });
            });
        }
    });
});

//Merge wallet
router.post("/supermerger", function(req, res) 
{
    console.log("INSIDE SUPER MERGER");
    var clientServerOptions = {
        uri: 'https://tms.ng/api/v1/dcba4321/wallets',
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Basic Y2FuYWFuOmtvbG9tb25pNDMyMSo='
        }
    }
    request(clientServerOptions, function (error, response) {
        if(error)
        {
            logger.info("ERROR: " + error);
            return;
        }else
        {
            var rResponse = JSON.parse(response.body);
            var ejarr = rResponse.data;
            console.log("LENGTH OF MERGER: " + ejarr.length);
            var len = ejarr.length;
            var count = 0;
            ejarr.forEach(function( ejarr ) {
                var qry = "SELECT * FROM walletactivies WHERE tid = $1 AND tousedate = $2";
                pool.query(qry, [ejarr.terminal_id, "2020-12-09"], (err, terminal) => {
                    if (err) 
                    {
                        console.log("NOT SUCCESSFUL 1x");
                        console.log(ejarr);
                        console.log(err);
                        console.log(count);
                        count = count + 1;
                        return;
                    }else
                    {
                        if(terminal.rows === undefined || terminal.rows.length === 1)
                        {
                            console.log("NO TODAY'S RECORD FOR TID: " + ejarr.terminal_id);
                            console.log("NO RECORD TOTAL FOR: " + ejarr.terminal_id + " IS " + ejarr.balance);
                            var qry2 =
                            "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                            pool.query(qry2, [ejarr.balance, ejarr.terminal_id], (err, resul) => {
                                if (err) 
                                {
                                    console.log("ERROR FOR WALLET UPDATE");
                                    console.log(ejarr);
                                    console.log(err);
                                    console.log(count);
                                    count = count + 1;
                                    return;
                                }else
                                {
                                    console.log("WALLET UPDATE SUCCESS: " + ejarr.terminal_id);
                                    console.log(count);
                                    count = count + 1;
                                    return;
                                }
                            });
                        }else
                        {
                            var wts = terminal.rows;
                            var wlen = terminal.rows.length;
                            var cco = 0;
                            var tot = ejarr.balance;
                            wts.forEach(function( wts ) {
                                if(wts.transmode === "DEBIT")
                                    tot = (parseFloat(tot) - parseFloat(wts.amount)).toFixed(2);
                                else
                                    tot = (parseFloat(tot) + parseFloat(wts.amount)).toFixed(2);
                                cco = cco + 1;
                                if(wlen === cco)
                                {
                                    console.log("TOTAL FOR: " + wts.tid + " IS " + tot);
                                    var qry2 =
                                    "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                                    pool.query(qry2, [tot, wts.tid], (err, resul) => {
                                        if (err) 
                                        {
                                            console.log("ERROR FOR WALLET UPDATE");
                                            console.log(ejarr);
                                            console.log(err);
                                            console.log(count);
                                            count = count + 1;
                                            return;
                                        }else
                                        {
                                            console.log("WALLET UPDATE SUCCESS: " + ejarr.terminal_id);
                                            console.log(count);
                                            count = count + 1;
                                            return;
                                        }
                                    });
                                }
                            });
                        }
                    }
                });
            });
        }
    });
});







//DISCO LOOKUP
router.get("/discolookup", function(req, res) 
{
    //return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});

    var tid = req.headers.tid;
    var servicecode = req.headers.servicecode; //DISCO LOOKUP
    var disco = req.headers.disco; //IKEDC, etc
    var meterno = req.headers.meterno;
    var discotype = req.headers.discotype; //EITHER POSTPAID OR PREPAID

    logger.info("DISCO LOOKUP");
    var qry = "SELECT * FROM terminalconfiguration WHERE tid = $1";
    pool.query(qry, [tid], (err, terminal) => {
        if (err) 
        {
            return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
        }else
        {
            if(terminal.rows === undefined || terminal.rows.length !== 1)
            {
                return res.status(500).send({"status": 500, "message": "Not Allowed"});
            }else
            {
                var sendout = new Object();
                sendout.serviceCode = servicecode;
                sendout.disco = disco;
                sendout.meterNo = meterno;
                sendout.discotype = discotype;
            
                var clientServerOptions = {
                    uri: url,
                    body: JSON.stringify(sendout),
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'hashKey': hash
                    }
                }
                request(clientServerOptions, function (error, response) {
                    if(error)
                    {
                        logger.info("ERROR: " + error);
                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Login Failed. Retry Later"});
                    }else
                    {
                        //console.log(response.statusCode);
                        var rResponse = JSON.parse(response.body);
                        return res.header("Content-Type",'Application/json').status(200).send(rResponse); 
                    }
                });
            }
        }
    });
});

//DISCO PAYMENT CASH
router.post("/paydiscocard", function(req, res) 
{
    var tid = req.body.tid;
    var servicecode = req.body.servicecode;
    var disco = req.body.disco;
    var meterno = req.body.meterno;
    var discotype = req.body.type;
    var amount = req.body.amount.replace(/,/g, '');
    var phonenumber = req.body.phonenumber;
    var name = req.body.name;
    var address = req.body.address;
    var rrn = req.body.rrn;
    
    console.log(req.body);
    logger.info("CARD DISCO PURCHASE");

    termRef = rrn;
    var transRef = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var qry = "SELECT * FROM terminalconfiguration WHERE tid = $1";
    pool.query(qry, [tid], (err, terminal) => {
        if (err) 
        {
            return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
        }else
        {
            if(terminal.rows === undefined || terminal.rows.length !== 1)
            {
                return res.status(500).send({"status": 500, "message": "Not Allowed"});
            }else
            {
                var sendout = new Object();
                sendout.serviceCode = servicecode;
                sendout.disco = disco;
                sendout.meterNo = meterno;
                sendout.type = discotype;
                sendout.amount = amount;
                sendout.phonenumber = phonenumber;
                sendout.name = name;
                sendout.address = address;
                sendout.request_id = rrn;
                
                var clientServerOptions = {
                    uri: url,
                    body: JSON.stringify(sendout),
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'hashKey': hash
                    }
                }
                request(clientServerOptions, function (error, response) {
                    if(error)
                    {
                        logger.info("ERROR: " + error);
                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Login Failed. Retry Later"});
                    }else
                    {
                        console.log(response);
                        var qry2 = "INSERT INTO toetranzact " + 
                            "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                            "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                            "cnumberc, others, status, amount)" + 
                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)";
                        pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "DATA", "NA", "NA", "",
                            "", "", "", "", "", "NA", "", "", "",
                            "", termRef, "Not Completed", amount], (err, resul) => {
                            if (err) 
                            {
                                console.log(err);
                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                            }else
                            {
                                rResponse = JSON.parse(response.body);
                                if(response.statusCode === 200 && rResponse.status === "200")
                                {
                                    var settled = ((parseFloat(terminal.rows[0].discos) / 100) * parseFloat(amount)).toFixed(2);
                                    var qry2 = "INSERT INTO frometranzact " + 
                                        "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                        "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                        "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, vatkar, varetzn, etranzactresponse, etranzactecho, mainamount, fee, ref)" + 
                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37)";
                                    pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "DISCO", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                        terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                        terminal.rows[0].accountname, transRef, "Transaction Success - CARD", amount, settled, "0.00", "0.00", "0.00", 
                                        "0.00", meterno + " - " + disco, "0.00", "0.00", "0.00", rResponse.message, JSON.stringify(rResponse), amount, "0.00", termRef], (err, resul) => {
                                        if (err) 
                                        {
                                            logger.info(err);
                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                            res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                        }else
                                        {
                                            var qry = "SELECT * FROM walletbalance WHERE tid = $1";
                                            pool.query(qry, [tid], (err, love) => { 
                                                if (err) 
                                                {
                                                    logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                    res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                }
                                                else
                                                {
                                                    var preBal = 0.00;
                                                    var newBal = 0.00;
                                                    if(love.rows === undefined || love.rows.length == 0)
                                                    {
                                                        preBal = 0.00;
                                                        newBal = settled;
                                                    }else
                                                    {    
                                                        preBal = love.rows[0].amount;
                                                        newBal = (parseFloat(settled) + parseFloat(love.rows[0].amount)).toFixed(2);
                                                    }
                                                    var waA = "INSERT INTO walletactivies " + 
                                                        "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                                                        "VALUES ($1, $2, $3, $4, $5, $6)";
                                                    pool.query(waA, [tid, settled, preBal, newBal, 
                                                        "CREDIT", meterno + " - " + disco + " - " + rResponse.message], (err, resul) => {
                                                        if (err) 
                                                        {
                                                            logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                            return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                        }else
                                                        {
                                                            if(love.rows === undefined || love.rows.length == 0)
                                                            {
                                                                var qry2 = "INSERT INTO walletbalance " + 
                                                                    "(tid, amount, accountname," +
                                                                        "accountbankcode, accountnumber, bankname, status, usertype, email) " + 
                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)";
                                                                pool.query(qry2, [tid, settled, terminal.rows[0].contactname, "NA",
                                                                "NA", "NA", "WALLET", "AGENT", terminal.rows[0].email], (err, resul) => {
                                                                    if (err) 
                                                                    {
                                                                        logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                        res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                    }else
                                                                    {
                                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                        pool.query(qry3, [tid, "", settled, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                            terminal.rows[0].instantvaluetime, "DISCO", 
                                                                            terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                                            terminal.rows[0].accountbank, "SETTLED", "agent" + tid, termRef], (err, resul) => {
                                                                            if (err) 
                                                                            {
                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                            }else
                                                                            {
                                                                                var qry9 = "INSERT INTO agentsettlement " + 
                                                                                    "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                pool.query(qry9, [tid, settled, terminal.rows[0].accountbank, 
                                                                                    terminal.rows[0].accountcode, terminal.rows[0].accountname, 
                                                                                    terminal.rows[0].accountnumber, JSON.stringify(rResponse.message), termRef], (err, resul) => {
                                                                                    if (err) 
                                                                                    {
                                                                                        logger.info("Txn Failed. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                        return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                    }else
                                                                                    {
                                                                                        logger.info("SUCCESSFUL DISCO CREDIT: " + data.body);
                                                                                        return res.header("Content-Type",'application/json').status(200).send(rResponse);
                                                                                    }
                                                                                });
                                                                            }
                                                                        });
                                                                    }
                                                                });
                                                            }else
                                                            {	
                                                                var sec = (parseFloat(settled) + parseFloat(love.rows[0].amount)).toFixed(2);
                                                                var qry2 =
                                                                    "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                                                                pool.query(qry2, [sec, tid], (err, resul) => {
                                                                    if (err) 
                                                                    {
                                                                        console.log(err)
                                                                        logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                        res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                    }else
                                                                    {
                                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                        pool.query(qry3, [tid, "", settled, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                            terminal.rows[0].instantvaluetime, "DISCO", 
                                                                            terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                                            terminal.rows[0].accountbank, "SETTLED", "agent" + tid, termRef], (err, resul) => {
                                                                            if (err) 
                                                                            {
                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                            }else
                                                                            {
                                                                                var qry9 = "INSERT INTO agentsettlement " + 
                                                                                    "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                pool.query(qry9, [tid, settled, terminal.rows[0].accountbank, 
                                                                                    terminal.rows[0].accountcode, terminal.rows[0].accountname, 
                                                                                    terminal.rows[0].accountnumber, JSON.stringify(rResponse.message), termRef], (err, resul) => {
                                                                                    if (err) 
                                                                                    {
                                                                                        logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                        logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                        return res.header("Content-Type",'Application/json').status(200).send(JSON.stringify(result));
                                                                                    }else
                                                                                    {
                                                                                        logger.info("SUCCESSFUL DISCO CREDIT: " + rResponse);
                                                                                        return res.header("Content-Type",'application/json').status(200).send(rResponse);
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
                                            });
                                        }
                                    });
                                }else
                                {    
                                    var qry3 = "INSERT INTO etranzactstatus " + 
                                        "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                                        "bankname, bankcode, accountnumber, status, transactiontype, ref)" + 
                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";
                                    pool.query(qry3, [rResponse.message, rResponse.status, JSON.stringify(rResponse), 
                                        rResponse, tid, amount, amount, 
                                        terminal.rows[0].accountbank, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                        "ERROR OCCURRED", disco + "-" + meterno + "DISCO FAILURE", termRef], (err, resul) => {
                                        if (err) 
                                        {
                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                            return res.header("Content-Type",'Application/json').status(500).send(rResponse);
                                        }else
                                        {
                                            var mailOptions = {
                                                from: emailHeading, // sender address
                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                replyTo: replyTo,
                                                subject: "tms DISCO CARD FAILURE", // Subject line
                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(rResponse) + "\n\n\nThe Request was: \n" + JSON.stringify(clientServerOptions), // plain text body with html format
                                            };
                                                
                                            transporter.sendMail(mailOptions, function(error, info){
                                                if (error) {
                                                    logger.info(error);
                                                } else {
                                                    logger.info('Email sent: ' + info.response);
                                                }
                                            });
                                            return res.header("Content-Type",'Application/json').status(500).send(rResponse);
                                        }
                                    });
                                } 
                            }
                        });
                    }
                });
            }
        }
    });
});

//DISCO PAYMENT WALLET
router.post("/paydiscowallet", function(req, res) 
{
    var tid = req.body.tid;
    var servicecode = req.body.servicecode;
    var disco = req.body.disco;
    var meterno = req.body.meterno;
    var discotype = req.body.type;
    var amount = req.body.amount.replace(/,/g, '');
    var phonenumber = req.body.phonenumber;
    var name = req.body.name;
    var address = req.body.address;
    var rrn = req.body.rrn;
    
    console.log(req.body);
    logger.info("CARD DISCO PURCHASE");

    termRef = rrn;
    var transRef = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var qry = "SELECT * FROM terminalconfiguration WHERE tid = $1";
    pool.query(qry, [tid], (err, terminal) => {
        if (err) 
        {
            return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
        }else
        {
            if(terminal.rows === undefined || terminal.rows.length !== 1)
            {
                return res.status(500).send({"status": 500, "message": "Not Allowed"});
            }else
            {
                var qry = "SELECT * FROM walletbalance WHERE tid = $1";
                pool.query(qry, [tid], (err, love) => { 
                    if (err) 
                    {
                        logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                        res.status(500).send({"status": 500, "message": "Transaction Failed."});
                    }
                    else
                    {
                        if(love.rows === undefined || love.rows.length == 0)
                        {
                            logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                            return res.status(500).send({"status": 500, "message": "No Funds Available"});
                        }else
                        {
                            var totAgentAmount = (parseFloat(love.rows[0].amount) - parseFloat(amount)).toFixed(2);
                            if(totAgentAmount < 0)
                            {
                                return res.status(500).send({"status": 500, "message": "Amount too high"});
                            }else
                            {
                                var sendout = new Object();
                                sendout.serviceCode = servicecode;
                                sendout.disco = disco;
                                sendout.meterNo = meterno;
                                sendout.type = discotype;
                                sendout.amount = amount;
                                sendout.phonenumber = phonenumber;
                                sendout.name = name;
                                sendout.address = address;
                                sendout.request_id = rrn;
                                
                                var clientServerOptions = {
                                    uri: url,
                                    body: JSON.stringify(sendout),
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                        'hashKey': hash
                                    }
                                }
                                request(clientServerOptions, function (error, response) {
                                    if(error)
                                    {
                                        logger.info("ERROR: " + error);
                                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Login Failed. Retry Later"});
                                    }else
                                    {
                                        console.log(response);
                                        var qry2 = "INSERT INTO toetranzact " + 
                                            "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                            "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                            "cnumberc, others, status, amount)" + 
                                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)";
                                        pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "DATA", "NA", "NA", "",
                                            "", "", "", "", "", "NA", "", "", "",
                                            "", termRef, "Not Completed", amount], (err, resul) => {
                                            if (err) 
                                            {
                                                console.log(err);
                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                            }else
                                            {
                                                rResponse = JSON.parse(response.body);
                                                if(response.statusCode === 200 && rResponse.status === "200")
                                                {
                                                    var settled = ((parseFloat(terminal.rows[0].discos) / 100) * parseFloat(amount)).toFixed(2);
                                                    var qry2 = "INSERT INTO frometranzact " + 
                                                        "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                                        "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                                        "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, vatkar, varetzn, etranzactresponse, etranzactecho, mainamount, fee, ref)" + 
                                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37)";
                                                    pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "DISCO", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                                        terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                        terminal.rows[0].accountname, transRef, "DEBIT SUCCESS", amount, settled, "0.00", "0.00", "0.00", 
                                                        "0.00", meterno + " - " + disco, "0.00", "0.00", "0.00", rResponse.message, JSON.stringify(rResponse), amount, "0.00", termRef], (err, resul) => {
                                                        if (err) 
                                                        {
                                                            logger.info(err);
                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                            res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                        }else
                                                        {
                                                            var preBal = 0.00;
                                                            var newBal = 0.00;
                                                            if(love.rows === undefined || love.rows.length == 0)
                                                                preBal = 0.00;
                                                            else
                                                                preBal = love.rows[0].amount;
                                                            newBal = parseFloat(totAgentAmount) + parseFloat(settled);
                                                            var waA = "INSERT INTO walletactivies " + 
                                                                "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                                                                "VALUES ($1, $2, $3, $4, $5, $6)";
                                                            pool.query(waA, [tid, amount, preBal, newBal, 
                                                                "DEBIT", meterno + " - " + disco + " - " + rResponse.message], (err, resul) => {
                                                                if (err) 
                                                                {
                                                                    logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                    return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                }else
                                                                {
                                                                    var qry = "SELECT * FROM walletbalance WHERE tid = $1";
                                                                    pool.query(qry, [tid], (err, love) => { 
                                                                        if (err) 
                                                                        {
                                                                            logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                            res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                        }
                                                                        else
                                                                        {
                                                                            if(love.rows === undefined || love.rows.length == 0)
                                                                            {
                                                                                var qry2 = "INSERT INTO walletbalance " + 
                                                                                    "(tid, amount, accountname," +
                                                                                        "accountbankcode, accountnumber, bankname, status, usertype, email) " + 
                                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)";
                                                                                pool.query(qry2, [tid, settled, terminal.rows[0].contactname, "NA",
                                                                                "NA", "NA", "WALLET", "AGENT", terminal.rows[0].email], (err, resul) => {
                                                                                    if (err) 
                                                                                    {
                                                                                        logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                        res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                    }else
                                                                                    {
                                                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                        pool.query(qry3, [tid, "", settled, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                            terminal.rows[0].instantvaluetime, "DISCO", 
                                                                                            terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                                                            terminal.rows[0].accountbank, "SETTLED", "agent" + tid, termRef], (err, resul) => {
                                                                                            if (err) 
                                                                                            {
                                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                            }else
                                                                                            {
                                                                                                var qry9 = "INSERT INTO agentsettlement " + 
                                                                                                    "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                                pool.query(qry9, [tid, settled, terminal.rows[0].accountbank, 
                                                                                                    terminal.rows[0].accountcode, terminal.rows[0].accountname, 
                                                                                                    terminal.rows[0].accountnumber, JSON.stringify(rResponse.message), termRef], (err, resul) => {
                                                                                                    if (err) 
                                                                                                    {
                                                                                                        logger.info("Txn Failed. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                        return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                                    }else
                                                                                                    {
                                                                                                        logger.info("SUCCESSFUL DISCO CREDIT: " + data.body);
                                                                                                        return res.header("Content-Type",'application/json').status(200).send(rResponse);
                                                                                                    }
                                                                                                });
                                                                                            }
                                                                                        });
                                                                                    }
                                                                                });
                                                                            }else
                                                                            {	
                                                                                var sec = (parseFloat(settled) + parseFloat(love.rows[0].amount)).toFixed(2);
                                                                                var qry2 =
                                                                                    "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                                                                                pool.query(qry2, [sec, tid], (err, resul) => {
                                                                                    if (err) 
                                                                                    {
                                                                                        console.log(err)
                                                                                        logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                        res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                    }else
                                                                                    {
                                                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                        pool.query(qry3, [tid, "", settled, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                            terminal.rows[0].instantvaluetime, "DISCO", 
                                                                                            terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                                                            terminal.rows[0].accountbank, "SETTLED", "agent" + tid, termRef], (err, resul) => {
                                                                                            if (err) 
                                                                                            {
                                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                            }else
                                                                                            {
                                                                                                var qry9 = "INSERT INTO agentsettlement " + 
                                                                                                    "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                                pool.query(qry9, [tid, settled, terminal.rows[0].accountbank, 
                                                                                                    terminal.rows[0].accountcode, terminal.rows[0].accountname, 
                                                                                                    terminal.rows[0].accountnumber, JSON.stringify(rResponse.message), termRef], (err, resul) => {
                                                                                                    if (err) 
                                                                                                    {
                                                                                                        logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                                        logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                        return res.header("Content-Type",'Application/json').status(200).send(JSON.stringify(result));
                                                                                                    }else
                                                                                                    {
                                                                                                        logger.info("SUCCESSFUL DISCO CREDIT: " + rResponse);
                                                                                                        return res.header("Content-Type",'application/json').status(200).send(rResponse);
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
                                                            });
                                                        }
                                                    });
                                                }else
                                                {    
                                                    var qry3 = "INSERT INTO etranzactstatus " + 
                                                        "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                                                        "bankname, bankcode, accountnumber, status, transactiontype, ref)" + 
                                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";
                                                    pool.query(qry3, [rResponse.message, rResponse.status, JSON.stringify(rResponse), 
                                                        rResponse, tid, amount, amount, 
                                                        terminal.rows[0].accountbank, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                        "ERROR OCCURRED", disco + "-" + meterno + "DISCO WALLET FAILURE", termRef], (err, resul) => {
                                                        if (err) 
                                                        {
                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                            return res.header("Content-Type",'Application/json').status(500).send(rResponse);
                                                        }else
                                                        {
                                                            var mailOptions = {
                                                                from: emailHeading, // sender address
                                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                replyTo: replyTo,
                                                                subject: "tms DISCO PURCHASE FAILURE", // Subject line
                                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(rResponse) + "\n\n\nThe Request was: \n" + JSON.stringify(clientServerOptions), // plain text body with html format
                                                            };
                                                                
                                                            transporter.sendMail(mailOptions, function(error, info){
                                                                if (error) {
                                                                    logger.info(error);
                                                                } else {
                                                                    logger.info('Email sent: ' + info.response);
                                                                }
                                                            });
                                                            return res.header("Content-Type",'Application/json').status(500).send(rResponse);
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
            }
        }
    });
});

//CABLE LOOKUP
router.get("/cablelookup", function(req, res) 
{
    //return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});

    var tid = req.headers.tid;
    var servicecode = req.headers.servicecode;
    var smartcardno = req.headers.smartcardno;
    var discotype = req.headers.type;

    logger.info("CABLE LOOKUP");
    var qry = "SELECT * FROM terminalconfiguration WHERE tid = $1";
    pool.query(qry, [tid], (err, terminal) => {
        if (err) 
        {
            return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
        }else
        {
            if(terminal.rows === undefined || terminal.rows.length !== 1)
            {
                return res.status(500).send({"status": 500, "message": "Not Allowed"});
            }else
            {
                var sendout = new Object();
                sendout.serviceCode = servicecode;
                sendout.smartCardNo = smartcardno;
                sendout.type = discotype;
            
                var clientServerOptions = {
                    uri: url,
                    body: JSON.stringify(sendout),
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'hashKey': hash
                    }
                }
                request(clientServerOptions, function (error, response) {
                    if(error)
                    {
                        logger.info("ERROR: " + error);
                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Login Failed. Retry Later"});
                    }else
                    {
                        //console.log(response.statusCode);
                        var rResponse = JSON.parse(response.body);
                        return res.header("Content-Type",'Application/json').status(200).send(rResponse); 
                    }
                });
            }
        }
    });
});

//CABLE PAYMENT CARD
router.post("/paycablecard", function(req, res) 
{
    var tid = req.body.tid;
    var servicecode = req.body.servicecode;
    var smartcardno = req.body.smartcardno;
    var customername = req.body.customername;
    var type = req.body.type;
    var amount = req.body.amount.replace(/,/g, '');
    var packagename = req.body.packagename;
    var productscode = req.body.productscode;
    var rrn = req.body.rrn;
    
    console.log(req.body);
    logger.info("CARD CABLE PURCHASE");

    termRef = rrn;
    var transRef = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var qry = "SELECT * FROM terminalconfiguration WHERE tid = $1";
    pool.query(qry, [tid], (err, terminal) => {
        if (err) 
        {
            return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
        }else
        {
            if(terminal.rows === undefined || terminal.rows.length !== 1)
            {
                return res.status(500).send({"status": 500, "message": "Not Allowed"});
            }else
            {
                var sendout = new Object();
                sendout.serviceCode = servicecode;
                sendout.smartCardNo = smartcardno;
                sendout.customerName = customername;
                sendout.type = type;
                sendout.amount = amount;
                sendout.packagename = packagename;
                sendout.productsCode = productscode;
                sendout.period = "1";
                sendout.hasAddon = "0";
                sendout.request_id = rrn;
                
                var clientServerOptions = {
                    uri: url,
                    body: JSON.stringify(sendout),
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'hashKey': hash
                    }
                }
                request(clientServerOptions, function (error, response) {
                    if(error)
                    {
                        logger.info("ERROR: " + error);
                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Login Failed. Retry Later"});
                    }else
                    {
                        //console.log(response);
                        var qry2 = "INSERT INTO toetranzact " + 
                            "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                            "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                            "cnumberc, others, status, amount)" + 
                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)";
                        pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "CABLE", "NA", "NA", "",
                            "", "", "", "", "", "NA", "", "", "",
                            "", termRef, "Not Completed", amount], (err, resul) => {
                            if (err) 
                            {
                                console.log(err);
                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                            }else
                            {
                                rResponse = JSON.parse(response.body);
                                if(response.statusCode === 200 && rResponse.status === "200")
                                {
                                    var settled = ((parseFloat(terminal.rows[0].cable) / 100) * parseFloat(amount)).toFixed(2);
                                    var qry2 = "INSERT INTO frometranzact " + 
                                        "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                        "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                        "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, vatkar, varetzn, etranzactresponse, etranzactecho, mainamount, fee, ref)" + 
                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37)";
                                    pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "CABLE", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                        terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                        terminal.rows[0].accountname, transRef, "Transaction Success - CARD", amount, settled, "0.00", "0.00", "0.00", 
                                        "0.00", packagename + " - " + productscode + " - " + type, "0.00", "0.00", "0.00", rResponse.message, JSON.stringify(rResponse), amount, "0.00", termRef], (err, resul) => {
                                        if (err) 
                                        {
                                            logger.info(err);
                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                            res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                        }else
                                        {
                                            var qry = "SELECT * FROM walletbalance WHERE tid = $1";
                                            pool.query(qry, [tid], (err, love) => { 
                                                if (err) 
                                                {
                                                    logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                    res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                }
                                                else
                                                {
                                                    var preBal = 0.00;
                                                    var newBal = 0.00;
                                                    if(love.rows === undefined || love.rows.length == 0)
                                                    {
                                                        preBal = 0.00;
                                                        newBal = settled;
                                                    }else
                                                    {    
                                                        preBal = love.rows[0].amount;
                                                        newBal = (parseFloat(settled) + parseFloat(love.rows[0].amount)).toFixed(2);
                                                    }
                                                    var waA = "INSERT INTO walletactivies " + 
                                                        "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                                                        "VALUES ($1, $2, $3, $4, $5, $6)";
                                                    pool.query(waA, [tid, settled, preBal, newBal, 
                                                        "CREDIT", packagename + " - " + productscode + " - " + type + " - " + rResponse.message], (err, resul) => {
                                                        if (err) 
                                                        {
                                                            logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                            return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                        }else
                                                        {
                                                            if(love.rows === undefined || love.rows.length == 0)
                                                            {
                                                                var qry2 = "INSERT INTO walletbalance " + 
                                                                    "(tid, amount, accountname," +
                                                                        "accountbankcode, accountnumber, bankname, status, usertype, email) " + 
                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)";
                                                                pool.query(qry2, [tid, settled, terminal.rows[0].contactname, "NA",
                                                                "NA", "NA", "WALLET", "AGENT", terminal.rows[0].email], (err, resul) => {
                                                                    if (err) 
                                                                    {
                                                                        logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                        res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                    }else
                                                                    {
                                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                        pool.query(qry3, [tid, "", settled, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                            terminal.rows[0].instantvaluetime, "CABLE", 
                                                                            terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                                            terminal.rows[0].accountbank, "SETTLED", "agent" + tid, termRef], (err, resul) => {
                                                                            if (err) 
                                                                            {
                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                            }else
                                                                            {
                                                                                var qry9 = "INSERT INTO agentsettlement " + 
                                                                                    "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                pool.query(qry9, [tid, settled, terminal.rows[0].accountbank, 
                                                                                    terminal.rows[0].accountcode, terminal.rows[0].accountname, 
                                                                                    terminal.rows[0].accountnumber, JSON.stringify(rResponse.message), termRef], (err, resul) => {
                                                                                    if (err) 
                                                                                    {
                                                                                        logger.info("Txn Failed. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                        return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                    }else
                                                                                    {
                                                                                        logger.info("SUCCESSFUL CABLE CREDIT: " + data.body);
                                                                                        return res.header("Content-Type",'application/json').status(200).send(rResponse);
                                                                                    }
                                                                                });
                                                                            }
                                                                        });
                                                                    }
                                                                });
                                                            }else
                                                            {	
                                                                var sec = (parseFloat(settled) + parseFloat(love.rows[0].amount)).toFixed(2);
                                                                var qry2 =
                                                                    "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                                                                pool.query(qry2, [sec, tid], (err, resul) => {
                                                                    if (err) 
                                                                    {
                                                                        console.log(err)
                                                                        logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                        res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                    }else
                                                                    {
                                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                        pool.query(qry3, [tid, "", settled, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                            terminal.rows[0].instantvaluetime, "CABLE", 
                                                                            terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                                            terminal.rows[0].accountbank, "SETTLED", "agent" + tid, termRef], (err, resul) => {
                                                                            if (err) 
                                                                            {
                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                            }else
                                                                            {
                                                                                var qry9 = "INSERT INTO agentsettlement " + 
                                                                                    "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                pool.query(qry9, [tid, settled, terminal.rows[0].accountbank, 
                                                                                    terminal.rows[0].accountcode, terminal.rows[0].accountname, 
                                                                                    terminal.rows[0].accountnumber, JSON.stringify(rResponse.message), termRef], (err, resul) => {
                                                                                    if (err) 
                                                                                    {
                                                                                        logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                        logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                        return res.header("Content-Type",'Application/json').status(200).send(JSON.stringify(result));
                                                                                    }else
                                                                                    {
                                                                                        logger.info("SUCCESSFUL CABLE CREDIT: " + rResponse);
                                                                                        return res.header("Content-Type",'application/json').status(200).send(rResponse);
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
                                            }); 
                                        }
                                    });
                                }else
                                {    
                                    var qry3 = "INSERT INTO etranzactstatus " + 
                                        "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                                        "bankname, bankcode, accountnumber, status, transactiontype, ref)" + 
                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";
                                    pool.query(qry3, [rResponse.message, rResponse.status, JSON.stringify(rResponse), 
                                        rResponse, tid, amount, amount, 
                                        terminal.rows[0].accountbank, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                        "ERROR OCCURRED", packagename + "-" + productscode + " - " + type + " CABLE FAILURE", termRef], (err, resul) => {
                                        if (err) 
                                        {
                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                            return res.header("Content-Type",'Application/json').status(500).send(rResponse);
                                        }else
                                        {
                                            var mailOptions = {
                                                from: emailHeading, // sender address
                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                replyTo: replyTo,
                                                subject: "tms CABLE CARD FAILURE", // Subject line
                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(rResponse) + "\n\n\nThe Request was: \n" + JSON.stringify(clientServerOptions), // plain text body with html format
                                            };
                                                
                                            transporter.sendMail(mailOptions, function(error, info){
                                                if (error) {
                                                    logger.info(error);
                                                } else {
                                                    logger.info('Email sent: ' + info.response);
                                                }
                                            });
                                            return res.header("Content-Type",'Application/json').status(500).send(rResponse);
                                        }
                                    });
                                } 
                            }
                        });
                    }
                });
            }
        }
    });
});

//CABLE PAYMENT WALLET
router.post("/paycablewallet", function(req, res) 
{
    var tid = req.body.tid;
    var servicecode = req.body.servicecode;
    var smartcardno = req.body.smartcardno;
    var customername = req.body.customername;
    var type = req.body.type;
    var amount = req.body.amount.replace(/,/g, '');
    var packagename = req.body.packagename;
    var productscode = req.body.productscode;
    var rrn = req.body.rrn;
    
    console.log(req.body);
    logger.info("WALLET CABLE PURCHASE");

    termRef = rrn;
    var transRef = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var qry = "SELECT * FROM terminalconfiguration WHERE tid = $1";
    pool.query(qry, [tid], (err, terminal) => {
        if (err) 
        {
            return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
        }else
        {
            if(terminal.rows === undefined || terminal.rows.length !== 1)
            {
                return res.status(500).send({"status": 500, "message": "Not Allowed"});
            }else
            {
                var qry = "SELECT * FROM walletbalance WHERE tid = $1";
                pool.query(qry, [tid], (err, love) => { 
                    if (err) 
                    {
                        logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                        res.status(500).send({"status": 500, "message": "Transaction Failed."});
                    }
                    else
                    {
                        if(love.rows === undefined || love.rows.length == 0)
                        {
                            logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                            return res.status(500).send({"status": 500, "message": "No Funds Available"});
                        }else
                        {
                            var totAgentAmount = (parseFloat(love.rows[0].amount) - parseFloat(amount)).toFixed(2);
                            if(totAgentAmount < 0)
                            {
                                return res.status(500).send({"status": 500, "message": "Amount too high"});
                            }else
                            {
                                var sendout = new Object();
                                sendout.serviceCode = servicecode;
                                sendout.smartCardNo = smartcardno;
                                sendout.customerName = customername;
                                sendout.type = type;
                                sendout.amount = amount;
                                sendout.packagename = packagename;
                                sendout.productsCode = productscode;
                                sendout.period = "1";
                                sendout.hasAddon = "0";
                                sendout.request_id = rrn;
                                
                                var clientServerOptions = {
                                    uri: url,
                                    body: JSON.stringify(sendout),
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                        'hashKey': hash
                                    }
                                }
                                request(clientServerOptions, function (error, response) {
                                    if(error)
                                    {
                                        logger.info("ERROR: " + error);
                                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Login Failed. Retry Later"});
                                    }else
                                    {
                                        //console.log(response);
                                        var qry2 = "INSERT INTO toetranzact " + 
                                            "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                            "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                            "cnumberc, others, status, amount)" + 
                                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)";
                                        pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "CABLE", "NA", "NA", "",
                                            "", "", "", "", "", "NA", "", "", "",
                                            "", termRef, "Not Completed", amount], (err, resul) => {
                                            if (err) 
                                            {
                                                console.log(err);
                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                            }else
                                            {
                                                rResponse = JSON.parse(response.body);
                                                if(response.statusCode === 200 && rResponse.status === "200")
                                                {
                                                    var settled = ((parseFloat(terminal.rows[0].cable) / 100) * parseFloat(amount)).toFixed(2);
                                                    var qry2 = "INSERT INTO frometranzact " + 
                                                        "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                                        "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                                        "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, vatkar, varetzn, etranzactresponse, etranzactecho, mainamount, fee, ref)" + 
                                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37)";
                                                    pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "CABLE", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                                        terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                        terminal.rows[0].accountname, transRef, "DEBIT SUCCESS", amount, settled, "0.00", "0.00", "0.00", 
                                                        "0.00", packagename + " - " + productscode + " - " + type, "0.00", "0.00", "0.00", rResponse.message, JSON.stringify(rResponse), amount, "0.00", termRef], (err, resul) => {
                                                        if (err) 
                                                        {
                                                            logger.info(err);
                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                            res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                        }else
                                                        {
                                                            var preBal = 0.00;
                                                            var newBal = 0.00;
                                                            if(love.rows === undefined || love.rows.length == 0)
                                                                preBal = 0.00;
                                                            else
                                                                preBal = love.rows[0].amount;
                                                            newBal = parseFloat(totAgentAmount) + parseFloat(settled);
                                                            var waA = "INSERT INTO walletactivies " + 
                                                                "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                                                                "VALUES ($1, $2, $3, $4, $5, $6)";
                                                            pool.query(waA, [tid, amount, preBal, newBal, 
                                                                "DEBIT", packagename + " - " + productscode + " - " + type + " - " + rResponse.message], (err, resul) => {
                                                                if (err) 
                                                                {
                                                                    logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                    return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                }else
                                                                {
                                                                    var qry = "SELECT * FROM walletbalance WHERE tid = $1";
                                                                    pool.query(qry, [tid], (err, love) => { 
                                                                        if (err) 
                                                                        {
                                                                            logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                            res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                        }
                                                                        else
                                                                        {
                                                                            if(love.rows === undefined || love.rows.length == 0)
                                                                            {
                                                                                var qry2 = "INSERT INTO walletbalance " + 
                                                                                    "(tid, amount, accountname," +
                                                                                        "accountbankcode, accountnumber, bankname, status, usertype, email) " + 
                                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)";
                                                                                pool.query(qry2, [tid, settled, terminal.rows[0].contactname, "NA",
                                                                                "NA", "NA", "WALLET", "AGENT", terminal.rows[0].email], (err, resul) => {
                                                                                    if (err) 
                                                                                    {
                                                                                        logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                        res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                    }else
                                                                                    {
                                                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                        pool.query(qry3, [tid, "", settled, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                            terminal.rows[0].instantvaluetime, "CABLE", 
                                                                                            terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                                                            terminal.rows[0].accountbank, "SETTLED", "agent" + tid, termRef], (err, resul) => {
                                                                                            if (err) 
                                                                                            {
                                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                            }else
                                                                                            {
                                                                                                var qry9 = "INSERT INTO agentsettlement " + 
                                                                                                    "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                                pool.query(qry9, [tid, settled, terminal.rows[0].accountbank, 
                                                                                                    terminal.rows[0].accountcode, terminal.rows[0].accountname, 
                                                                                                    terminal.rows[0].accountnumber, JSON.stringify(rResponse.message), termRef], (err, resul) => {
                                                                                                    if (err) 
                                                                                                    {
                                                                                                        logger.info("Txn Failed. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                        return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                                    }else
                                                                                                    {
                                                                                                        logger.info("SUCCESSFUL CABLE CREDIT: " + data.body);
                                                                                                        return res.header("Content-Type",'application/json').status(200).send(rResponse);
                                                                                                    }
                                                                                                });
                                                                                            }
                                                                                        });
                                                                                    }
                                                                                });
                                                                            }else
                                                                            {	
                                                                                var sec = (parseFloat(settled) + parseFloat(love.rows[0].amount)).toFixed(2);
                                                                                var qry2 =
                                                                                    "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                                                                                pool.query(qry2, [sec, tid], (err, resul) => {
                                                                                    if (err) 
                                                                                    {
                                                                                        console.log(err)
                                                                                        logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                        res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                    }else
                                                                                    {
                                                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                        pool.query(qry3, [tid, "", settled, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                            terminal.rows[0].instantvaluetime, "CABLE", 
                                                                                            terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                                                            terminal.rows[0].accountbank, "SETTLED", "agent" + tid, termRef], (err, resul) => {
                                                                                            if (err) 
                                                                                            {
                                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                            }else
                                                                                            {
                                                                                                var qry9 = "INSERT INTO agentsettlement " + 
                                                                                                    "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                                pool.query(qry9, [tid, settled, terminal.rows[0].accountbank, 
                                                                                                    terminal.rows[0].accountcode, terminal.rows[0].accountname, 
                                                                                                    terminal.rows[0].accountnumber, JSON.stringify(rResponse.message), termRef], (err, resul) => {
                                                                                                    if (err) 
                                                                                                    {
                                                                                                        logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                                        logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                        return res.header("Content-Type",'Application/json').status(200).send(JSON.stringify(result));
                                                                                                    }else
                                                                                                    {
                                                                                                        logger.info("SUCCESSFUL CABLE CREDIT: " + rResponse);
                                                                                                        return res.header("Content-Type",'application/json').status(200).send(rResponse);
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
                                                            });
                                                        }
                                                    });
                                                }else
                                                {    
                                                    var qry3 = "INSERT INTO etranzactstatus " + 
                                                        "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                                                        "bankname, bankcode, accountnumber, status, transactiontype, ref)" + 
                                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";
                                                    pool.query(qry3, [rResponse.message, rResponse.status, JSON.stringify(rResponse), 
                                                        rResponse, tid, amount, amount, 
                                                        terminal.rows[0].accountbank, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                        "ERROR OCCURRED", packagename + "-" + productscode + " - " + type + " CABLE WALLET FAILURE", termRef], (err, resul) => {
                                                        if (err) 
                                                        {
                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                            return res.header("Content-Type",'Application/json').status(500).send(rResponse);
                                                        }else
                                                        {
                                                            var mailOptions = {
                                                                from: emailHeading, // sender address
                                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                replyTo: replyTo,
                                                                subject: "tms CABLE PURCHASE FAILURE", // Subject line
                                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(rResponse) + "\n\n\nThe Request was: \n" + JSON.stringify(clientServerOptions), // plain text body with html format
                                                            };
                                                                
                                                            transporter.sendMail(mailOptions, function(error, info){
                                                                if (error) {
                                                                    logger.info(error);
                                                                } else {
                                                                    logger.info('Email sent: ' + info.response);
                                                                }
                                                            });
                                                            return res.header("Content-Type",'Application/json').status(500).send(rResponse);
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
            }
        }
    });
});

//INTERNET LOOKUP
router.get("/internetlookup", function(req, res) 
{
    //return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
    
    var tid = req.headers.tid;
    var servicecode = req.headers.servicecode;
    var account = req.headers.account;
    var discotype = req.headers.type;

    logger.info("INTERNET LOOKUP");
    var qry = "SELECT * FROM terminalconfiguration WHERE tid = $1";
    pool.query(qry, [tid], (err, terminal) => {
        if (err) 
        {
            return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
        }else
        {
            if(terminal.rows === undefined || terminal.rows.length !== 1)
            {
                return res.status(500).send({"status": 500, "message": "Not Allowed"});
            }else
            {
                var sendout = new Object();
                sendout.serviceCode = servicecode;
                sendout.account = account;
                sendout.type = discotype;
            
                var clientServerOptions = {
                    uri: url,
                    body: JSON.stringify(sendout),
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'hashKey': hash
                    }
                }
                request(clientServerOptions, function (error, response) {
                    if(error)
                    {
                        logger.info("ERROR: " + error);
                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Login Failed. Retry Later"});
                    }else
                    {
                        //console.log(response.statusCode);
                        var rResponse = JSON.parse(response.body);
                        return res.header("Content-Type",'Application/json').status(200).send(rResponse); 
                    }
                });
            }
        }
    });
});

//INTERNET PAYMENT CASH
router.post("/payinternetcard", function(req, res) 
{
    var tid = req.body.tid;
    var servicecode = req.body.servicecode;
    var package = req.body.package; //name from validation
    var account = req.body.account;
    var type = req.body.type; //SMILE_BUNDLE
    var productscode = req.body.code; //code from validation
    var amount = req.body.amount.replace(/,/g, '');
    var bundle = req.body.allowance;//allowance from validation
    var rrn = req.body.rrn;
    
    console.log(req.body);
    logger.info("CARD INTERNET PURCHASE");

    termRef = rrn;
    var transRef = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var qry = "SELECT * FROM terminalconfiguration WHERE tid = $1";
    pool.query(qry, [tid], (err, terminal) => {
        if (err) 
        {
            return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
        }else
        {
            if(terminal.rows === undefined || terminal.rows.length !== 1)
            {
                return res.status(500).send({"status": 500, "message": "Not Allowed"});
            }else
            {
                var sendout = new Object();
                sendout.serviceCode = servicecode;
                sendout.package = package;
                sendout.account = account;
                sendout.type = type;
                sendout.productsCode = productscode;
                sendout.amount = amount;
                sendout.bundle = bundle;
                sendout.request_id = rrn;
                
                console.log(sendout);
                var clientServerOptions = {
                    uri: url,
                    body: JSON.stringify(sendout),
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'hashKey': hash
                    }
                }
                request(clientServerOptions, function (error, response) {
                    if(error)
                    {
                        logger.info("ERROR: " + error);
                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Login Failed. Retry Later"});
                    }else
                    {
                        //console.log(response);
                        var qry2 = "INSERT INTO toetranzact " + 
                            "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                            "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                            "cnumberc, others, status, amount)" + 
                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)";
                        pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "INTERNET", "NA", "NA", "",
                            "", "", "", "", "", "NA", "", "", "",
                            "", termRef, "Not Completed", amount], (err, resul) => {
                            if (err) 
                            {
                                console.log(err);
                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                            }else
                            {
                                rResponse = JSON.parse(response.body);
                                if(response.statusCode === 200 && rResponse.status === "200")
                                {
                                    var settled = ((parseFloat(terminal.rows[0].internet) / 100) * parseFloat(amount)).toFixed(2);
                                    var qry2 = "INSERT INTO frometranzact " + 
                                        "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                        "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                        "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, vatkar, varetzn, etranzactresponse, etranzactecho, mainamount, fee, ref)" + 
                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37)";
                                    pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "INTERNET", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                        terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                        terminal.rows[0].accountname, transRef, "Transaction Success - CARD", amount, settled, "0.00", "0.00", "0.00", 
                                        "0.00", account + " - " + package + " - " + type, "0.00", "0.00", "0.00", rResponse.message, JSON.stringify(rResponse), amount, "0.00", termRef], (err, resul) => {
                                        if (err) 
                                        {
                                            logger.info(err);
                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                            res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                        }else
                                        {
                                            var qry = "SELECT * FROM walletbalance WHERE tid = $1";
                                            pool.query(qry, [tid], (err, love) => { 
                                                if (err) 
                                                {
                                                    logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                    res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                }
                                                else
                                                {
                                                    var preBal = 0.00;
                                                    var newBal = 0.00;
                                                    if(love.rows === undefined || love.rows.length == 0)
                                                    {
                                                        preBal = 0.00;
                                                        newBal = settled;
                                                    }else
                                                    {    
                                                        preBal = love.rows[0].amount;
                                                        newBal = (parseFloat(settled) + parseFloat(love.rows[0].amount)).toFixed(2);
                                                    }
                                                    var waA = "INSERT INTO walletactivies " + 
                                                        "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                                                        "VALUES ($1, $2, $3, $4, $5, $6)";
                                                    pool.query(waA, [tid, settled, preBal, newBal, 
                                                        "CREDIT", account + " - " + package + " - " + type + " - " + rResponse.message], (err, resul) => {
                                                        if (err) 
                                                        {
                                                            logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                            return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                        }else
                                                        {
                                                            if(love.rows === undefined || love.rows.length == 0)
                                                            {
                                                                var qry2 = "INSERT INTO walletbalance " + 
                                                                    "(tid, amount, accountname," +
                                                                        "accountbankcode, accountnumber, bankname, status, usertype, email) " + 
                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)";
                                                                pool.query(qry2, [tid, settled, terminal.rows[0].contactname, "NA",
                                                                "NA", "NA", "WALLET", "AGENT", terminal.rows[0].email], (err, resul) => {
                                                                    if (err) 
                                                                    {
                                                                        logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                        res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                    }else
                                                                    {
                                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                        pool.query(qry3, [tid, "", settled, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                            terminal.rows[0].instantvaluetime, "INTERNET", 
                                                                            terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                                            terminal.rows[0].accountbank, "SETTLED", "agent" + tid, termRef], (err, resul) => {
                                                                            if (err) 
                                                                            {
                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                            }else
                                                                            {
                                                                                var qry9 = "INSERT INTO agentsettlement " + 
                                                                                    "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                pool.query(qry9, [tid, settled, terminal.rows[0].accountbank, 
                                                                                    terminal.rows[0].accountcode, terminal.rows[0].accountname, 
                                                                                    terminal.rows[0].accountnumber, JSON.stringify(rResponse.message), termRef], (err, resul) => {
                                                                                    if (err) 
                                                                                    {
                                                                                        logger.info("Txn Failed. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                        return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                    }else
                                                                                    {
                                                                                        logger.info("SUCCESSFUL INTERNET CREDIT: " + data.body);
                                                                                        return res.header("Content-Type",'application/json').status(200).send(rResponse);
                                                                                    }
                                                                                });
                                                                            }
                                                                        });
                                                                    }
                                                                });
                                                            }else
                                                            {	
                                                                var sec = (parseFloat(settled) + parseFloat(love.rows[0].amount)).toFixed(2);
                                                                var qry2 =
                                                                    "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                                                                pool.query(qry2, [sec, tid], (err, resul) => {
                                                                    if (err) 
                                                                    {
                                                                        console.log(err)
                                                                        logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                        res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                    }else
                                                                    {
                                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                        pool.query(qry3, [tid, "", settled, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                            terminal.rows[0].instantvaluetime, "INTERNET", 
                                                                            terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                                            terminal.rows[0].accountbank, "SETTLED", "agent" + tid, termRef], (err, resul) => {
                                                                            if (err) 
                                                                            {
                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                            }else
                                                                            {
                                                                                var qry9 = "INSERT INTO agentsettlement " + 
                                                                                    "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                pool.query(qry9, [tid, settled, terminal.rows[0].accountbank, 
                                                                                    terminal.rows[0].accountcode, terminal.rows[0].accountname, 
                                                                                    terminal.rows[0].accountnumber, JSON.stringify(rResponse.message), termRef], (err, resul) => {
                                                                                    if (err) 
                                                                                    {
                                                                                        logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                        logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                        return res.header("Content-Type",'Application/json').status(200).send(JSON.stringify(result));
                                                                                    }else
                                                                                    {
                                                                                        logger.info("SUCCESSFUL INTERNET CREDIT: " + rResponse);
                                                                                        return res.header("Content-Type",'application/json').status(200).send(rResponse);
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
                                            });
                                        }
                                    });
                                }else
                                {    
                                    var qry3 = "INSERT INTO etranzactstatus " + 
                                        "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                                        "bankname, bankcode, accountnumber, status, transactiontype, ref)" + 
                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";
                                    pool.query(qry3, [rResponse.message, rResponse.status, JSON.stringify(rResponse), 
                                        rResponse, tid, amount, amount, 
                                        terminal.rows[0].accountbank, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                        "ERROR OCCURRED", account + "-" + package + " - " + type + " INTERNET FAILURE", termRef], (err, resul) => {
                                        if (err) 
                                        {
                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                            return res.header("Content-Type",'Application/json').status(500).send(rResponse);
                                        }else
                                        {
                                            var mailOptions = {
                                                from: emailHeading, // sender address
                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                replyTo: replyTo,
                                                subject: "tms INTERNET CARD FAILURE", // Subject line
                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(rResponse) + "\n\n\nThe Request was: \n" + JSON.stringify(clientServerOptions), // plain text body with html format
                                            };
                                                
                                            transporter.sendMail(mailOptions, function(error, info){
                                                if (error) {
                                                    logger.info(error);
                                                } else {
                                                    logger.info('Email sent: ' + info.response);
                                                }
                                            });
                                            return res.header("Content-Type",'Application/json').status(500).send(rResponse);
                                        }
                                    });
                                } 
                            }
                        });
                    }
                });
            }
        }
    });
});

//INTERNET PAYMENT WALLET
router.post("/payinternetwallet", function(req, res) 
{
    var tid = req.body.tid;
    var servicecode = req.body.servicecode;
    var package = req.body.package; //name from validation
    var account = req.body.account;
    var type = req.body.type; //SMILE_BUNDLE
    var productscode = req.body.code; //code from validation
    var amount = req.body.amount.replace(/,/g, '');
    var bundle = req.body.allowance;//allowance from validation
    var rrn = req.body.rrn;
    
    console.log(req.body);
    logger.info("WALLET CABLE PURCHASE");

    termRef = rrn;
    var transRef = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var qry = "SELECT * FROM terminalconfiguration WHERE tid = $1";
    pool.query(qry, [tid], (err, terminal) => {
        if (err) 
        {
            return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
        }else
        {
            if(terminal.rows === undefined || terminal.rows.length !== 1)
            {
                return res.status(500).send({"status": 500, "message": "Not Allowed"});
            }else
            {
                var qry = "SELECT * FROM walletbalance WHERE tid = $1";
                pool.query(qry, [tid], (err, love) => { 
                    if (err) 
                    {
                        logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                        res.status(500).send({"status": 500, "message": "Transaction Failed."});
                    }
                    else
                    {
                        if(love.rows === undefined || love.rows.length == 0)
                        {
                            logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                            return res.status(500).send({"status": 500, "message": "No Funds Available"});
                        }else
                        {
                            var totAgentAmount = (parseFloat(love.rows[0].amount) - parseFloat(amount)).toFixed(2);
                            if(totAgentAmount < 0)
                            {
                                return res.status(500).send({"status": 500, "message": "Amount too high"});
                            }else
                            {
                                var sendout = new Object();
                                sendout.serviceCode = servicecode;
                                sendout.package = package;
                                sendout.account = account;
                                sendout.type = type;
                                sendout.productsCode = productscode;
                                sendout.amount = amount;
                                sendout.bundle = bundle;
                                sendout.request_id = rrn;
                                
                                var clientServerOptions = {
                                    uri: url,
                                    body: JSON.stringify(sendout),
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                        'hashKey': hash
                                    }
                                }
                                request(clientServerOptions, function (error, response) {
                                    if(error)
                                    {
                                        logger.info("ERROR: " + error);
                                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Login Failed. Retry Later"});
                                    }else
                                    {
                                        //console.log(response);
                                        var qry2 = "INSERT INTO toetranzact " + 
                                            "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                            "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                            "cnumberc, others, status, amount)" + 
                                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)";
                                        pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "INTERNET", "NA", "NA", "",
                                            "", "", "", "", "", "NA", "", "", "",
                                            "", termRef, "Not Completed", amount], (err, resul) => {
                                            if (err) 
                                            {
                                                console.log(err);
                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                            }else
                                            {
                                                rResponse = JSON.parse(response.body);
                                                if(response.statusCode === 200 && rResponse.status === "200")
                                                {
                                                    var settled = ((parseFloat(terminal.rows[0].internet) / 100) * parseFloat(amount)).toFixed(2);
                                                    var qry2 = "INSERT INTO frometranzact " + 
                                                        "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                                        "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                                        "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, vatkar, varetzn, etranzactresponse, etranzactecho, mainamount, fee, ref)" + 
                                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37)";
                                                    pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "INTERNET", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                                        terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                        terminal.rows[0].accountname, transRef, "DEBIT SUCCESS", amount, settled, "0.00", "0.00", "0.00", 
                                                        "0.00", account + " - " + package + " - " + type, "0.00", "0.00", "0.00", rResponse.message, JSON.stringify(rResponse), amount, "0.00", termRef], (err, resul) => {
                                                        if (err) 
                                                        {
                                                            logger.info(err);
                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                            res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                        }else
                                                        {
                                                            var preBal = 0.00;
                                                            var newBal = 0.00;
                                                            if(love.rows === undefined || love.rows.length == 0)
                                                                preBal = 0.00;
                                                            else
                                                                preBal = love.rows[0].amount;
                                                            newBal = parseFloat(totAgentAmount) + parseFloat(settled);
                                                            var waA = "INSERT INTO walletactivies " + 
                                                                "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                                                                "VALUES ($1, $2, $3, $4, $5, $6)";
                                                            pool.query(waA, [tid, amount, preBal, newBal, 
                                                                "DEBIT", account + " - " + package + " - " + type + " - " + rResponse.message], (err, resul) => {
                                                                if (err) 
                                                                {
                                                                    logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                    return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                }else
                                                                {
                                                                    var qry = "SELECT * FROM walletbalance WHERE tid = $1";
                                                                    pool.query(qry, [tid], (err, love) => { 
                                                                        if (err) 
                                                                        {
                                                                            logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                            res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                        }
                                                                        else
                                                                        {
                                                                            if(love.rows === undefined || love.rows.length == 0)
                                                                            {
                                                                                var qry2 = "INSERT INTO walletbalance " + 
                                                                                    "(tid, amount, accountname," +
                                                                                        "accountbankcode, accountnumber, bankname, status, usertype, email) " + 
                                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)";
                                                                                pool.query(qry2, [tid, settled, terminal.rows[0].contactname, "NA",
                                                                                "NA", "NA", "WALLET", "AGENT", terminal.rows[0].email], (err, resul) => {
                                                                                    if (err) 
                                                                                    {
                                                                                        logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                        res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                    }else
                                                                                    {
                                                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                        pool.query(qry3, [tid, "", settled, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                            terminal.rows[0].instantvaluetime, "INTERNET", 
                                                                                            terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                                                            terminal.rows[0].accountbank, "SETTLED", "agent" + tid, termRef], (err, resul) => {
                                                                                            if (err) 
                                                                                            {
                                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                            }else
                                                                                            {
                                                                                                var qry9 = "INSERT INTO agentsettlement " + 
                                                                                                    "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                                pool.query(qry9, [tid, settled, terminal.rows[0].accountbank, 
                                                                                                    terminal.rows[0].accountcode, terminal.rows[0].accountname, 
                                                                                                    terminal.rows[0].accountnumber, JSON.stringify(rResponse.message), termRef], (err, resul) => {
                                                                                                    if (err) 
                                                                                                    {
                                                                                                        logger.info("Txn Failed. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                        return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                                    }else
                                                                                                    {
                                                                                                        logger.info("SUCCESSFUL INTERNET CREDIT: " + data.body);
                                                                                                        return res.header("Content-Type",'application/json').status(200).send(rResponse);
                                                                                                    }
                                                                                                });
                                                                                            }
                                                                                        });
                                                                                    }
                                                                                });
                                                                            }else
                                                                            {	
                                                                                var sec = (parseFloat(settled) + parseFloat(love.rows[0].amount)).toFixed(2);
                                                                                var qry2 =
                                                                                    "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                                                                                pool.query(qry2, [sec, tid], (err, resul) => {
                                                                                    if (err) 
                                                                                    {
                                                                                        console.log(err)
                                                                                        logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                        res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                    }else
                                                                                    {
                                                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                        pool.query(qry3, [tid, "", settled, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                            terminal.rows[0].instantvaluetime, "INTERNET", 
                                                                                            terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                                                            terminal.rows[0].accountbank, "SETTLED", "agent" + tid, termRef], (err, resul) => {
                                                                                            if (err) 
                                                                                            {
                                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                            }else
                                                                                            {
                                                                                                var qry9 = "INSERT INTO agentsettlement " + 
                                                                                                    "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                                pool.query(qry9, [tid, settled, terminal.rows[0].accountbank, 
                                                                                                    terminal.rows[0].accountcode, terminal.rows[0].accountname, 
                                                                                                    terminal.rows[0].accountnumber, JSON.stringify(rResponse.message), termRef], (err, resul) => {
                                                                                                    if (err) 
                                                                                                    {
                                                                                                        logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                                        logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                        return res.header("Content-Type",'Application/json').status(200).send(JSON.stringify(result));
                                                                                                    }else
                                                                                                    {
                                                                                                        logger.info("SUCCESSFUL INTERNET CREDIT: " + rResponse);
                                                                                                        return res.header("Content-Type",'application/json').status(200).send(rResponse);
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
                                                            });
                                                        }
                                                    });
                                                }else
                                                {    
                                                    var qry3 = "INSERT INTO etranzactstatus " + 
                                                        "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                                                        "bankname, bankcode, accountnumber, status, transactiontype, ref)" + 
                                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";
                                                    pool.query(qry3, [rResponse.message, rResponse.status, JSON.stringify(rResponse), 
                                                        rResponse, tid, amount, amount, 
                                                        terminal.rows[0].accountbank, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                        "ERROR OCCURRED", account + "-" + package + " - " + type + " INTERNET WALLET FAILURE", termRef], (err, resul) => {
                                                        if (err) 
                                                        {
                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                            return res.header("Content-Type",'Application/json').status(500).send(rResponse);
                                                        }else
                                                        {
                                                            var mailOptions = {
                                                                from: emailHeading, // sender address
                                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                replyTo: replyTo,
                                                                subject: "tms INTERNET PURCHASE FAILURE", // Subject line
                                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(rResponse) + "\n\n\nThe Request was: \n" + JSON.stringify(clientServerOptions), // plain text body with html format
                                                            };
                                                                
                                                            transporter.sendMail(mailOptions, function(error, info){
                                                                if (error) {
                                                                    logger.info(error);
                                                                } else {
                                                                    logger.info('Email sent: ' + info.response);
                                                                }
                                                            });
                                                            return res.header("Content-Type",'Application/json').status(500).send(rResponse);
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
            }
        }
    });
});



module.exports.router = router;