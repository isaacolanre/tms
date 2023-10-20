var router = express.Router();
var request = require('request').defaults({ rejectUnauthorized: false });

var vtuusername = "info@sagecloud.ng";
var vtupassword = "dev@tms";
var vtuurl = "https://mycreditme.com";
var vtupin = "3186";

function isNumber(str) {
    if (typeof str != "string") 
        return false
    return !isNaN(str) && !isNaN(parseFloat(str))
}

//DELETE
//VTU CARD
//OKAY
router.get("/cardvtu", function(req, res) 
{
    var tid = req.headers.tid;
    var provider = req.headers.provider;//VTU
    var destination = req.headers.destination;//Phone Number to credit
    var amount = req.headers.amount.replace(/,/g, '');
    var termRef = req.headers.rrn;

    logger.info("VTU PAYMENT");
    logger.info(req.headers);

    var rrn = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

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
			    sendout.username = vtuusername;
                sendout.password = vtupassword;
            
                var clientServerOptions = {
                    uri: vtuurl + "/api/user/login",
                    body: JSON.stringify(sendout),
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
                request(clientServerOptions, function (error, response) {
                    if(error)
                    {
                        logger.info("ERROR: " + error);
                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Login Failed. Retry Later"});
                    }else
                    {
                        var qry2 = "INSERT INTO toetranzact " + 
                            "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                            "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                            "cnumberc, others, status, amount)" + 
                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)";
                        pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "VTU", "NA", "NA", "",
                            "", "", "", "", "", "NA", "", "", "",
                            "", termRef, "Not Completed", amount], (err, resul) => {
                            if (err) 
                            {
                                console.log(err);
                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                            }else
                            {
                                var rResponse = JSON.parse(response.body);
                                sendout = new Object();
                                sendout.phoneNumber = destination;
                                sendout.amount = parseInt(amount);
                                sendout.pin = vtupin;
                                sendout.key = sha256('3186@tmsNG');
                                sendout.service = provider;
        
                                var clientServerOptions = {
                                    uri: vtuurl + "/api/product/1",
                                    body: JSON.stringify(sendout),
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                        'Authorization': 'bearer ' + rResponse.token,
                                        'x-api-key': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.VFVab1drNHlXWFZDV1hoRFJrUTFiRzlvWm1RMlZXSXdabTFWWmxrclNGSjZXRXN3ZEZCQmNsaFdjVlJFTjJ3d2NrTnRWMDVMT1cxd1RtOUpNSEo1TDFkdVpIaHlSRWcxYXpCREwxQmtNRGw0WTNkWFYyWkVSbFF4VFZoTllWZHJNbUZtYzJnMFQyNDFiVTU1T1RGWmMwdHNXSHBNYmpRNFZuaEtOVkZZY1dkNVpXVlFTbU5RV2xaWU5YUXlOWFl4VEhKRlNuaEhWbkYyWjFaTE5qWjBTVGxUTWxNMlkwTm5NMko2TDBWVFQyOUNjMlZ0VlVFd05FdHBNMnBuZVZKT1VqZzBkVlpIWm5aWVVrSjJUSFprWjJkbVpVSXJZMDR2TVVWMlYxaFNSRVkyVlhKeGJEWnFOMGsyWmxSbVJtRklUMXBVYlZCWGNVNHJPVzFrTkVweFluZzJZamxOYm5FNU5USlJaemhWT0ZodmREZG9XWGM5UFE9PQ%3D%3D.d7d40b515caad503dbb109de9be2aca9f9dbbf7f0fc2a014f615b6d225358306'
                                    }
                                }
                                //console.log(clientServerOptions);
                                request(clientServerOptions, function (error, data) {
                                    if(error)
                                    {
                                        logger.info("ERROR: " + error);
                                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Getting Value Failed. Retry Later"});
                                    }else
                                    {
                                        var rResponse;
                                        var hh = false;
                                        var d = data.body.slice(0, 1);
                                        if(d !== "<")
                                        {
                                            hh = true;
                                            rResponse = JSON.parse(data.body);
                                        }else
                                            rResponse = data.body;
                                        if(hh && rResponse.status === 1)
                                        {
                                            var qry2 = "INSERT INTO frometranzact " + 
                                                "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                                "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                                "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, vatkar, varetzn, etranzactresponse, etranzactecho, mainamount, fee, ref)" + 
                                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37)";
                                            pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "VTU", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                                terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                terminal.rows[0].accountname, transRef, "Transaction Success - CARD", amount, "0.00", "0.00", "0.00", "0.00", 
                                                "0.00", destination + " - " + provider, "0.00", "0.00", "0.00", rResponse.message, rResponse, amount, "0.00", termRef], (err, resul) => {
                                                if (err) 
                                                {
                                                    logger.info(err);
                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                }else
                                                {
                                                    var settled = ((parseFloat(terminal.rows[0].vtu) / 100) * parseFloat(amount)).toFixed(2);
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
                                                                "CREDIT", destination + " - " + provider + " - " + rResponse.message], (err, resul) => {
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
                                                                                    terminal.rows[0].instantvaluetime, "VTU", 
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
                                                                                                logger.info("SUCCESSFUL VTU CREDIT: " + data.body);
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
                                                                                    terminal.rows[0].instantvaluetime, "VTU", 
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
                                                                                                logger.info("SUCCESSFUL VTU CREDIT: " + data.body);
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
                                            pool.query(qry3, [rResponse, rResponse, rResponse, 
                                                rResponse, tid, amount, amount, 
                                                terminal.rows[0].accountbank, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                "ERROR OCCURRED", provider + "-" + destination + "-VTU", termRef], (err, resul) => {
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
                                                        subject: "tms VTU CARD FAILURE", // Subject line
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
                });
            }
        }
    });
});

//DELETE
//VTU WALLET
//OKAY
router.get("/wallet/vtu", function(req, res) 
{
    var tid = req.headers.tid;
    var provider = req.headers.provider;//VTU
    var destination = req.headers.destination;//Phone Number to credit
    var amount = req.headers.amount.replace(/,/g, '');
    
    logger.info("WALLET VTU PAYMENT");
    logger.info(req.headers);

    var termRef = randomstring.generate({
        length: 12,
        charset: 'numeric'
    });

    var rrn = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    console.log(req.headers);
    if(isNumber(amount) === false)
    {
        console.log(req.headers);
        return res.status(500).send({"status": 500, "message": "Invalid Amount. Retry Later"});
    }else
    {
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
                                    sendout.username = vtuusername;
                                    sendout.password = vtupassword;
                                
                                    var clientServerOptions = {
                                        uri: vtuurl + "/api/user/login",
                                        body: JSON.stringify(sendout),
                                        method: 'POST',
                                        headers: {
                                            'Content-Type': 'application/json'
                                        }
                                    }
                                    request(clientServerOptions, function (error, response) {
                                        if(error)
                                        {
                                            logger.info("ERROR: " + error);
                                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Login Failed. Retry Later"});
                                        }else
                                        {
                                            var qry2 = "INSERT INTO toetranzact " + 
                                                "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                                "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                                "cnumberc, others, status, amount)" + 
                                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)";
                                            pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "VTU", "NA", "NA", "",
                                                "", "", "", "", "", "NA", "", "", "",
                                                "", termRef, "Not Completed", amount], (err, resul) => {
                                                if (err) 
                                                {
                                                    console.log(err);
                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                }else
                                                {
                                                    var rResponse = JSON.parse(response.body);
                                                    sendout = new Object();
                                                    sendout.phoneNumber = destination;
                                                    sendout.amount = parseInt(amount);
                                                    sendout.pin = vtupin;
                                                    sendout.key = sha256('3186@tmsNG');
                                                    sendout.service = provider;
                            
                                                    var clientServerOptions = {
                                                        uri: vtuurl + "/api/product/1",
                                                        body: JSON.stringify(sendout),
                                                        method: 'POST',
                                                        headers: {
                                                            'Content-Type': 'application/json',
                                                            'Authorization': 'bearer ' + rResponse.token,
                                                            'x-api-key': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.VFVab1drNHlXWFZDV1hoRFJrUTFiRzlvWm1RMlZXSXdabTFWWmxrclNGSjZXRXN3ZEZCQmNsaFdjVlJFTjJ3d2NrTnRWMDVMT1cxd1RtOUpNSEo1TDFkdVpIaHlSRWcxYXpCREwxQmtNRGw0WTNkWFYyWkVSbFF4VFZoTllWZHJNbUZtYzJnMFQyNDFiVTU1T1RGWmMwdHNXSHBNYmpRNFZuaEtOVkZZY1dkNVpXVlFTbU5RV2xaWU5YUXlOWFl4VEhKRlNuaEhWbkYyWjFaTE5qWjBTVGxUTWxNMlkwTm5NMko2TDBWVFQyOUNjMlZ0VlVFd05FdHBNMnBuZVZKT1VqZzBkVlpIWm5aWVVrSjJUSFprWjJkbVpVSXJZMDR2TVVWMlYxaFNSRVkyVlhKeGJEWnFOMGsyWmxSbVJtRklUMXBVYlZCWGNVNHJPVzFrTkVweFluZzJZamxOYm5FNU5USlJaemhWT0ZodmREZG9XWGM5UFE9PQ%3D%3D.d7d40b515caad503dbb109de9be2aca9f9dbbf7f0fc2a014f615b6d225358306'
                                                        }
                                                    }
                                                    //console.log(clientServerOptions);
                                                    request(clientServerOptions, function (error, data) {
                                                        if(error)
                                                        {
                                                            logger.info("ERROR: " + error);
                                                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Getting Value Failed. Retry Later"});
                                                        }else
                                                        {
                                                            var rResponse;
                                                            var hh = false;
                                                            var d = data.body.slice(0, 1);
                                                            if(d !== "<")
                                                            {
                                                                hh = true;
                                                                rResponse = JSON.parse(data.body);
                                                            }else
                                                                rResponse = data.body;
                                                            if(hh && rResponse.status === 1)
                                                            {
                                                                var qry2 = "INSERT INTO frometranzact " + 
                                                                    "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                                                    "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                                                    "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, vatkar, varetzn, etranzactresponse, etranzactecho, mainamount, fee, ref)" + 
                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37)";
                                                                pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "VTU", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                                                    terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                                    terminal.rows[0].accountname, transRef, "DEBIT SUCCESS", amount, "0.00", "0.00", "0.00", "0.00", 
                                                                    "0.00", destination + " - " + provider, "0.00", "0.00", "0.00", rResponse.message, rResponse, amount, "0.00", termRef], (err, resul) => {
                                                                    if (err) 
                                                                    {
                                                                        logger.info(err);
                                                                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                        res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
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
                                                                            "DEBIT", destination + " - " + provider + " - " + rResponse.message], (err, resul) => {
                                                                            if (err) 
                                                                            {
                                                                                logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                            }else
                                                                            {
                                                                                var qry2 =
                                                                                    "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                                                                                pool.query(qry2, [totAgentAmount, tid], (err, resul) => {
                                                                                    if (err) 
                                                                                    {
                                                                                        logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                        return res.status(500).send({"status": 500, "message": "An Error Occurred..."});
                                                                                    }else
                                                                                    {
                                                                                        var settled = ((parseFloat(terminal.rows[0].vtu) / 100) * parseFloat(amount)).toFixed(2);
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
                                                                                                                terminal.rows[0].instantvaluetime, "VTU", 
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
                                                                                                                            logger.info("SUCCESSFUL VTU CREDIT: " + data.body);
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
                                                                                                                terminal.rows[0].instantvaluetime, "VTU", 
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
                                                                                                                            logger.info("SUCCESSFUL VTU CREDIT: " + data.body);
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
                                                                    }
                                                                });
                                                            }else
                                                            {    
                                                                var qry3 = "INSERT INTO etranzactstatus " + 
                                                                    "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                                                                    "bankname, bankcode, accountnumber, status, transactiontype, ref)" + 
                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";
                                                                pool.query(qry3, [rResponse, rResponse, rResponse, 
                                                                    rResponse, tid, amount, amount, 
                                                                    terminal.rows[0].accountbank, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                                    "ERROR OCCURRED", provider + "-" + destination + "-VTU", termRef], (err, resul) => {
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
                                                                            subject: "tms VTU CARD FAILURE", // Subject line
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
                                    });
                                }
                            }
                        }
                    });
                }
            }
        });

    }
});

//DATA LOOKUP
//OKAY
router.get("/datalookup", function(req, res) 
{
    var tid = req.headers.tid;
    var service = req.headers.service; //AIRTELDATA, MTNDATA, 9MOBILEDATA, GLODATA

    logger.info("DATA LOOKUP");

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
			    sendout.username = vtuusername;
                sendout.password = vtupassword;
            
                var clientServerOptions = {
                    uri: vtuurl + "/api/user/login",
                    body: JSON.stringify(sendout),
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
                request(clientServerOptions, function (error, response) {
                    if(error)
                    {
                        logger.info("ERROR: " + error);
                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Login Failed. Retry Later"});
                    }else
                    {
                        var rResponse = JSON.parse(response.body);
                        sendout = new Object();
                        sendout.service = service;

                        var clientServerOptions = {
                            uri: vtuurl + "/api/data/lookup",
                            body: JSON.stringify(sendout),
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': 'bearer ' + rResponse.token,
                                'x-api-key': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.VFVab1drNHlXWFZDV1hoRFJrUTFiRzlvWm1RMlZXSXdabTFWWmxrclNGSjZXRXN3ZEZCQmNsaFdjVlJFTjJ3d2NrTnRWMDVMT1cxd1RtOUpNSEo1TDFkdVpIaHlSRWcxYXpCREwxQmtNRGw0WTNkWFYyWkVSbFF4VFZoTllWZHJNbUZtYzJnMFQyNDFiVTU1T1RGWmMwdHNXSHBNYmpRNFZuaEtOVkZZY1dkNVpXVlFTbU5RV2xaWU5YUXlOWFl4VEhKRlNuaEhWbkYyWjFaTE5qWjBTVGxUTWxNMlkwTm5NMko2TDBWVFQyOUNjMlZ0VlVFd05FdHBNMnBuZVZKT1VqZzBkVlpIWm5aWVVrSjJUSFprWjJkbVpVSXJZMDR2TVVWMlYxaFNSRVkyVlhKeGJEWnFOMGsyWmxSbVJtRklUMXBVYlZCWGNVNHJPVzFrTkVweFluZzJZamxOYm5FNU5USlJaemhWT0ZodmREZG9XWGM5UFE9PQ%3D%3D.d7d40b515caad503dbb109de9be2aca9f9dbbf7f0fc2a014f615b6d225358306'
                            }
                        }
                        request(clientServerOptions, function (error, data) {
                            if(error)
                            {
                                logger.info("ERROR: " + error);
                                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Getting Value Failed. Retry Later"});
                            }else
                            {
                                var rResponse;
                                var hh = false;
                                var d = data.body.slice(0, 1);
                                if(d !== "<")
                                {
                                    hh = true;
                                    rResponse = JSON.parse(data.body);
                                }else
                                    rResponse = data.body;
                                if(hh && rResponse.status === 1)
                                {
                                    logger.info("SUCCESSFUL VTU CREDIT: " + data.body);
                                    return res.header("Content-Type",'application/json').status(200).send(rResponse);
                                }else
                                {    
                                    var qry3 = "INSERT INTO etranzactstatus " + 
                                        "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                                        "bankname, bankcode, accountnumber, status, transactiontype, ref)" + 
                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";
                                    pool.query(qry3, [rResponse, rResponse, rResponse, 
                                        rResponse, tid, amount, amount, 
                                        terminal.rows[0].accountbank, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                        "ERROR OCCURRED", provider + "-" + destination + "-VTU", termRef], (err, resul) => {
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
                                                subject: "tms DATA LOOKUP FAILURE", // Subject line
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

//DELETE
//CARD DATA CONSUMPTION
//OKAY
router.get("/datapurchase", function(req, res) 
{
    var tid = req.headers.tid;
    var provider = req.headers.provider;//SERVICE NAME EG AIRTELDATA, MTNDATA, GLODATA etc
    var destination = req.headers.destination;//Phone Number to credit
    var amount = req.headers.amount.replace(/,/g, '');
    var termRef = req.headers.rrn;
    var code = req.headers.code;//CODE GOT FROM DATA SERVICE LOOKUP

    console.log(req.headers);
    logger.info("DATA PURCHASE CARD");
    var rrn = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

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
			    sendout.username = vtuusername;
                sendout.password = vtupassword;
            
                var clientServerOptions = {
                    uri: vtuurl + "/api/user/login",
                    body: JSON.stringify(sendout),
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
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
                                var rResponse = JSON.parse(response.body);
                                sendout = new Object();
                                sendout.phoneNumber = destination;
                                sendout.amount = parseInt(amount);
                                sendout.pin = vtupin;
                                sendout.key = sha256('3186@tmsNG');
                                sendout.service = provider;
                                sendout.code = code;

                                var clientServerOptions = {
                                    uri: vtuurl + "/api/data/purchase",
                                    body: JSON.stringify(sendout),
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                        'Authorization': 'bearer ' + rResponse.token,
                                        'x-api-key': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.VFVab1drNHlXWFZDV1hoRFJrUTFiRzlvWm1RMlZXSXdabTFWWmxrclNGSjZXRXN3ZEZCQmNsaFdjVlJFTjJ3d2NrTnRWMDVMT1cxd1RtOUpNSEo1TDFkdVpIaHlSRWcxYXpCREwxQmtNRGw0WTNkWFYyWkVSbFF4VFZoTllWZHJNbUZtYzJnMFQyNDFiVTU1T1RGWmMwdHNXSHBNYmpRNFZuaEtOVkZZY1dkNVpXVlFTbU5RV2xaWU5YUXlOWFl4VEhKRlNuaEhWbkYyWjFaTE5qWjBTVGxUTWxNMlkwTm5NMko2TDBWVFQyOUNjMlZ0VlVFd05FdHBNMnBuZVZKT1VqZzBkVlpIWm5aWVVrSjJUSFprWjJkbVpVSXJZMDR2TVVWMlYxaFNSRVkyVlhKeGJEWnFOMGsyWmxSbVJtRklUMXBVYlZCWGNVNHJPVzFrTkVweFluZzJZamxOYm5FNU5USlJaemhWT0ZodmREZG9XWGM5UFE9PQ%3D%3D.d7d40b515caad503dbb109de9be2aca9f9dbbf7f0fc2a014f615b6d225358306'
                                    }
                                }
                                //console.log(clientServerOptions);
                                request(clientServerOptions, function (error, data) {
                                    if(error)
                                    {
                                        logger.info("ERROR: " + error);
                                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Getting Value Failed. Retry Later"});
                                    }else
                                    {
                                        var rResponse;
                                        var hh = false;
                                        var d = data.body.slice(0, 1);
                                        if(d !== "<")
                                        {
                                            hh = true;
                                            rResponse = JSON.parse(data.body);
                                        }else
                                            rResponse = data.body;
                                        if(hh && rResponse.status === 1)
                                        {
                                            var settled = ((parseFloat(terminal.rows[0].data) / 100) * parseFloat(amount)).toFixed(2);
                                            var qry2 = "INSERT INTO frometranzact " + 
                                                "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                                "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                                "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, vatkar, varetzn, etranzactresponse, etranzactecho, mainamount, fee, ref)" + 
                                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37)";
                                            pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "DATA", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                                terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                terminal.rows[0].accountname, transRef, "Transaction Success - CARD", amount, settled, "0.00", "0.00", "0.00", 
                                                "0.00", destination + " - " + provider, "0.00", "0.00", "0.00", rResponse.message, rResponse, amount, "0.00", termRef], (err, resul) => {
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
                                                                "CREDIT", destination + " - " + provider + " - " + rResponse.message], (err, resul) => {
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
                                                                                    terminal.rows[0].instantvaluetime, "DATA", 
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
                                                                                                logger.info("SUCCESSFUL VTU CREDIT: " + data.body);
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
                                                                                    terminal.rows[0].instantvaluetime, "DATA", 
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
                                                                                                logger.info("SUCCESSFUL VTU CREDIT: " + data.body);
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
                                            pool.query(qry3, [rResponse, rResponse, rResponse, 
                                                rResponse, tid, amount, amount, 
                                                terminal.rows[0].accountbank, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                "ERROR OCCURRED", provider + "-" + destination + "-VTU-DATA-PURCHASE", termRef], (err, resul) => {
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
                                                        subject: "tms DATA PURCHASE FAILURE", // Subject line
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
                });
            }
        }
    });
});

//DELETE
//WALLET DATA PURCHASE
//OKAY
router.get("/buywithwallet", function(req, res) 
{
    var tid = req.headers.tid;
    var provider = req.headers.provider;//SERVICE NAME EG AIRTELDATA, MTNDATA, GLODATA etc
    var destination = req.headers.destination;//Phone Number to credit
    var amount = req.headers.amount.replace(/,/g, '');
    var code = req.headers.code;//CODE GOT FROM DATA SERVICE LOOKUP

    logger.info("DATA PURCHASE WALLET");

    var termRef = randomstring.generate({
        length: 12,
        charset: 'numeric'
    });

    var rrn = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    console.log(req.headers);
    
    if(isNumber(amount) === false)
    {
        console.log(req.headers);
        return res.status(500).send({"status": 500, "message": "Invalid Amount. Retry Later"});
    }else
    {
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
                                    sendout.username = vtuusername;
                                    sendout.password = vtupassword;
                                
                                    var clientServerOptions = {
                                        uri: vtuurl + "/api/user/login",
                                        body: JSON.stringify(sendout),
                                        method: 'POST',
                                        headers: {
                                            'Content-Type': 'application/json'
                                        }
                                    }
                                    request(clientServerOptions, function (error, response) {
                                        if(error)
                                        {
                                            logger.info("ERROR: " + error);
                                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Login Failed. Retry Later"});
                                        }else
                                        {
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
                                                    var rResponse = JSON.parse(response.body);
                                                    sendout = new Object();
                                                    sendout.phoneNumber = destination;
                                                    sendout.amount = parseInt(amount);
                                                    sendout.pin = vtupin;
                                                    sendout.key = sha256('3186@tmsNG');
                                                    sendout.service = provider;
                                                    sendout.code = code;

                                                    var clientServerOptions = {
                                                        uri: vtuurl + "/api/data/purchase",
                                                        body: JSON.stringify(sendout),
                                                        method: 'POST',
                                                        headers: {
                                                            'Content-Type': 'application/json',
                                                            'Authorization': 'bearer ' + rResponse.token,
                                                            'x-api-key': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.VFVab1drNHlXWFZDV1hoRFJrUTFiRzlvWm1RMlZXSXdabTFWWmxrclNGSjZXRXN3ZEZCQmNsaFdjVlJFTjJ3d2NrTnRWMDVMT1cxd1RtOUpNSEo1TDFkdVpIaHlSRWcxYXpCREwxQmtNRGw0WTNkWFYyWkVSbFF4VFZoTllWZHJNbUZtYzJnMFQyNDFiVTU1T1RGWmMwdHNXSHBNYmpRNFZuaEtOVkZZY1dkNVpXVlFTbU5RV2xaWU5YUXlOWFl4VEhKRlNuaEhWbkYyWjFaTE5qWjBTVGxUTWxNMlkwTm5NMko2TDBWVFQyOUNjMlZ0VlVFd05FdHBNMnBuZVZKT1VqZzBkVlpIWm5aWVVrSjJUSFprWjJkbVpVSXJZMDR2TVVWMlYxaFNSRVkyVlhKeGJEWnFOMGsyWmxSbVJtRklUMXBVYlZCWGNVNHJPVzFrTkVweFluZzJZamxOYm5FNU5USlJaemhWT0ZodmREZG9XWGM5UFE9PQ%3D%3D.d7d40b515caad503dbb109de9be2aca9f9dbbf7f0fc2a014f615b6d225358306'
                                                        }
                                                    }
                                                    //console.log(clientServerOptions);
                                                    request(clientServerOptions, function (error, data) {
                                                        if(error)
                                                        {
                                                            logger.info("ERROR: " + error);
                                                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Getting Value Failed. Retry Later"});
                                                        }else
                                                        {
                                                            var rResponse;
                                                            var hh = false;
                                                            var d = data.body.slice(0, 1);
                                                            if(d !== "<")
                                                            {
                                                                hh = true;
                                                                rResponse = JSON.parse(data.body);
                                                            }else
                                                                rResponse = data.body;
                                                            if(hh && rResponse.status === 1)
                                                            {
                                                                var settled = ((parseFloat(terminal.rows[0].data) / 100) * parseFloat(amount)).toFixed(2);
                                                                var qry2 = "INSERT INTO frometranzact " + 
                                                                    "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                                                    "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                                                    "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, vatkar, varetzn, etranzactresponse, etranzactecho, mainamount, fee, ref)" + 
                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37)";
                                                                pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "DATA", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                                                    terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                                    terminal.rows[0].accountname, transRef, "DEBIT SUCCESS", amount, settled, "0.00", "0.00", "0.00", 
                                                                    "0.00", destination + " - " + provider, "0.00", "0.00", "0.00", rResponse.message, rResponse, amount, "0.00", termRef], (err, resul) => {
                                                                    if (err) 
                                                                    {
                                                                        logger.info(err);
                                                                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                        res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
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
                                                                            "DEBIT", destination + " - " + provider + " - " + rResponse.message], (err, resul) => {
                                                                            if (err) 
                                                                            {
                                                                                logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                            }else
                                                                            {
                                                                                var qry2 =
                                                                                    "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                                                                                pool.query(qry2, [totAgentAmount, tid], (err, resul) => {
                                                                                    if (err) 
                                                                                    {
                                                                                        logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                        return res.status(500).send({"status": 500, "message": "An Error Occurred..."});
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
                                                                                                                terminal.rows[0].instantvaluetime, "DATA", 
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
                                                                                                                            logger.info("SUCCESSFUL VTU CREDIT: " + data.body);
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
                                                                                                                terminal.rows[0].instantvaluetime, "DATA", 
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
                                                                                                                            logger.info("SUCCESSFUL VTU CREDIT: " + data.body);
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
                                                                    }
                                                                });
                                                            }else
                                                            {    
                                                                var qry3 = "INSERT INTO etranzactstatus " + 
                                                                    "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                                                                    "bankname, bankcode, accountnumber, status, transactiontype, ref)" + 
                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";
                                                                pool.query(qry3, [rResponse, rResponse, rResponse, 
                                                                    rResponse, tid, amount, amount, 
                                                                    terminal.rows[0].accountbank, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                                    "ERROR OCCURRED", provider + "-" + destination + "-VTU-DATA-PURCHASE", termRef], (err, resul) => {
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
                                                                            subject: "tms DATA PURCHASE FAILURE", // Subject line
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
                                    });
                                }
                            }
                        }
                    });
                }
            }
        });

    }

});


const wsdlURL = "https://ebank2.gtbank.com/GapsFileUploader_pilot/FileUploader.asmx";
var tmsAmount = "20.00";

//DELETE
//CASH OUT
router.get("/cashwithdrawal", function(req, res) 
{
    var tid = req.headers.tid;
    var amount = parseFloat(req.headers.amount.replace(/,/g, ''));
    var tmsfee = req.headers.tmsfee;
    var superagentfee = req.headers.superagentfee;
    var mainamount = req.headers.mainamount.replace(/,/g, '');
    var rrn = req.headers.rrn;
    var fee = req.headers.fee;
    var supersuperfee = req.headers.supersuperfee;

    var transRef = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    logger.info("INSIDE CASH WITHDRAWAL");
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
                var supersuper = 0.00;
                var vatKar = 0.00;
                var etzn = 0.00;
                var vatEtzn = 0.00;
                var agentamount = 0.00;

                var usemsc = 0.00;
                var stamp = 0.00;

                var cast = "";
                var sast = "";
                var ssst = "";

                if(parseFloat(tmsfee) <= 0)
                {
                    cast = "SETTLED";
                    tmsfee = 0.00;
                }else
                {
                    cast = "NOT SETTLED";
                    tmsfee = ((parseFloat(tmsfee) / 100) * parseFloat(amount)).toFixed(2);
                }
                
                if(parseFloat(superagentfee) <= 0)
                {
                    sast = "SETTLED";
                    superagentfee = 0.00;
                }else
                {
                    sast = "NOT SETTLED";
                    superagentfee = ((parseFloat(superagentfee) / 100) * parseFloat(amount)).toFixed(2);
                }

                if(parseFloat(supersuperfee) <= 0)
                {
                    ssst = "SETTLED";
                    supersuper = 0.00;
                }else
                {    
                    ssst = "NOT SETTLED";
                    supersuper = ((parseFloat(supersuperfee) / 100) * parseFloat(amount)).toFixed(2);
                    supersuperfee = supersuper;
                }

                var tamt = parseFloat(tmsfee) + parseFloat(superagentfee) + parseFloat(supersuper);
                console.log("TOTAL: " + tamt);
                if(parseFloat(tamt) >= parseFloat(terminal.rows[0].wdcapped))
                {
                    console.log("INSIDE 00000");
                    superagentfee = parseFloat(terminal.rows[0].wdsharesa);
                    supersuper = parseFloat(terminal.rows[0].wdsharess)
                    tmsfee = (parseFloat(terminal.rows[0].wdcapped) - superagentfee - supersuper).toFixed(2);
                    cast = "NOT SETTLED";
                    if(parseFloat(superagentfee) <= 0)
                        sast = "SETTLED";
                    else
                        sast = "NOT SETTLED";

                    if(parseFloat(supersuper) <= 0)
                        ssst = "SETTLED";
                    else
                        ssst = "NOT SETTLED";
                }else
                {
                    console.log("OUTSIDE 00000");
                }

                agentamount = (parseFloat(amount) - parseFloat(tmsfee) - 
                    parseFloat(superagentfee) - parseFloat(supersuper)).toFixed(2);
                if(1) 
                {
                    var qry2 = "INSERT INTO frometranzact " + 
                        "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                        "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                        "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, stampduty, mainamount, fee, vatkar, varetzn, ref)" + 
                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36)";
                    pool.query(qry2, ["", "", "", rrn, tid, "", "CASH WITHDRAWAL", terminal.rows[0].caaccountnumber, 
                        terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                        terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, 
                        terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, 
                        rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                        terminal.rows[0].accountname, transRef, "DEBIT SUCCESS", amount, agentamount, superagentfee, 
                        tmsfee, usemsc, terminal.rows[0].switchfee, "NA", "0.00", stamp, mainamount, fee, vatKar, supersuper, rrn], (err, resul) => {
                        if (err) 
                        {
                            console.log(err);
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
                                        newBal = agentamount;
                                    }else
                                    {  
                                        preBal = love.rows[0].amount;
                                        newBal = (parseFloat(love.rows[0].amount) + parseFloat(agentamount)).toFixed(2);
                                    }
                                    var waA = "INSERT INTO walletactivies " + 
                                        "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                                        "VALUES ($1, $2, $3, $4, $5, $6)";
                                    pool.query(waA, [tid, agentamount, preBal, newBal, 
                                        "CREDIT", "CASH WITHDRAWAL"], (err, resul) => {
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
                                                pool.query(qry2, [tid, agentamount, terminal.rows[0].contactname, "NA",
                                                "NA", "NA", "WALLET", 
                                                    "AGENT", terminal.rows[0].email], (err, resul) => {
                                                    if (err) 
                                                    {
                                                        logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                        res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                    }else
                                                    {
                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype" +
                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                        pool.query(qry3, [tid, "", superagentfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                            terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                                            terminal.rows[0].saaccountname, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountnumber,
                                                            terminal.rows[0].saaccountbank, sast, "superagent" + tid], (err, resul) => {
                                                            if (err) 
                                                            {
                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                            }else
                                                            {
                                                                var qry3 = "INSERT INTO agencyinstant " + 
                                                                    "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                    "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype" +
                                                                    ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                pool.query(qry3, [tid, "", tmsfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                    terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                                                    terminal.rows[0].caaccountname, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountnumber,
                                                                    terminal.rows[0].caaccountbank, cast, "tms" + tid], (err, resul) => {
                                                                    if (err) 
                                                                    {
                                                                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                        res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                    }else
                                                                    {
                                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype" +
                                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                        pool.query(qry3, [tid, "", supersuper, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                            terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                                                            terminal.rows[0].superaccountname, terminal.rows[0].superaccountcode, 
                                                                            terminal.rows[0].superaccountnumber,
                                                                            terminal.rows[0].superbankname, ssst, "supersuper" + tid], (err, resul) => {
                                                                            if (err) 
                                                                            {
                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                            }else
                                                                            {
                                                                                logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                return res.status(200).send({"status": 200, "message": "Successfully Added."});
                                                                            }
                                                                        });
                                                                    }
                                                                });
                                                            }
                                                        });
                                                    }
                                                });
                                            }else
                                            {
                                                var totAgentAmount = (parseFloat(love.rows[0].amount) + parseFloat(agentamount)).toFixed(2);
                                                var qry2 =
                                                    "UPDATE walletbalance SET amount = $1, accountname = $2, accountbankcode = $3," + 
                                                    "accountnumber = $4, bankname = $5, status = $6, usertype = $7 WHERE tid = $8";
                                                pool.query(qry2, [totAgentAmount, terminal.rows[0].contactname, "NA",
                                                "NA", "NA", "WALLET", 
                                                    "AGENT", tid], (err, resul) => {
                                                    if (err) 
                                                    {
                                                        console.log(err)
                                                        logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                        res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                    }else
                                                    {
                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype" +
                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                        pool.query(qry3, [tid, "", superagentfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                            terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                                            terminal.rows[0].saaccountname, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountnumber,
                                                            terminal.rows[0].saaccountbank, sast, "superagent" + tid], (err, resul) => {
                                                            if (err) 
                                                            {
                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                            }else
                                                            {
                                                                var qry3 = "INSERT INTO agencyinstant " + 
                                                                    "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                    "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype" +
                                                                    ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                pool.query(qry3, [tid, "", tmsfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                    terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                                                    terminal.rows[0].caaccountname, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountnumber,
                                                                    terminal.rows[0].caaccountbank, cast, "tms" + tid], (err, resul) => {
                                                                    if (err) 
                                                                    {
                                                                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                        res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                    }else
                                                                    {
                                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype" +
                                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                        pool.query(qry3, [tid, "", supersuper, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                            terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                                                            terminal.rows[0].superaccountname, terminal.rows[0].superaccountcode, 
                                                                            terminal.rows[0].superaccountnumber,
                                                                            terminal.rows[0].superbankname, ssst, "supersuper" + tid], (err, resul) => {
                                                                            if (err) 
                                                                            {
                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                            }else
                                                                            {
                                                                                logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                return res.status(200).send({"status": 200, "message": "Successfully Added."});
                                                                            }
                                                                        });
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
                }
            }
        }
    });
});

//DELETE
//PENDING CASHOUT
//CASH OUT
router.post("/pendwithdrawal", function(req, res) 
{
    console.log(req.body);
    var json = JSON.parse(JSON.stringify(req.body));
    var tid = json.tid;
    var amount = parseFloat(json.amount.replace(/,/g, ''));
    var tmsfee = json.tmsfee;
    var superagentfee = json.superagentfee;
    var mainamount = json.mainamount.replace(/,/g, '');
    var rrn = json.rrn;
    var fee = json.fee;
    var supersuperfee = json.supersuperfee;

    logger.info("INSIDE PENDING CASH WITHDRAWAL");
    logger.info(req.body);
    if(rrn === undefined || rrn === null || rrn.length != 12)
    {
        console.log("RRN ERROR");
        return res.status(200).send({"status": 200, "message": "RRN ERROR."});
    }else
    {
        var transRef = randomstring.generate({
            length: 11,
            charset: 'numeric'
        });
    
        var qry = "SELECT * FROM terminalconfiguration WHERE tid = $1";
        pool.query(qry, [tid], (err, terminal) => {
            if (err) 
            {
                return res.status(200).send({"status": 200, "message": "An Error Occurred. Not Successful."});
            }else
            {
                if(terminal.rows === undefined || terminal.rows.length !== 1)
                {
                    return res.status(200).send({"status": 200, "message": "Not Allowed"});
                }else
                {
                    var supersuper = 0.00;
                    var vatKar = 0.00;
                    var etzn = 0.00;
                    var vatEtzn = 0.00;
                    var agentamount = 0.00;
    
                    var usemsc = 0.00;
                    var stamp = 0.00;
    
                    var cast = "";
                    var sast = "";
                    var ssst = "";
    
                    if(parseFloat(tmsfee) <= 0)
                    {
                        cast = "SETTLED";
                        tmsfee = 0.00;
                    }else
                    {
                        cast = "NOT SETTLED";
                        tmsfee = ((parseFloat(tmsfee) / 100) * parseFloat(amount)).toFixed(2);
                    }
                    
                    if(parseFloat(superagentfee) <= 0)
                    {
                        sast = "SETTLED";
                        superagentfee = 0.00;
                    }else
                    {
                        sast = "NOT SETTLED";
                        superagentfee = ((parseFloat(superagentfee) / 100) * parseFloat(amount)).toFixed(2);
                    }
    
                    if(parseFloat(supersuperfee) <= 0)
                    {
                        ssst = "SETTLED";
                        supersuper = 0.00;
                    }else
                    {    
                        ssst = "NOT SETTLED";
                        supersuper = ((parseFloat(supersuperfee) / 100) * parseFloat(amount)).toFixed(2);
                        supersuperfee = supersuper;
                    }
    
                    var tamt = parseFloat(tmsfee) + parseFloat(superagentfee) + parseFloat(supersuper);
                    console.log("TOTAL: " + tamt);
                    if(parseFloat(tamt) >= parseFloat(terminal.rows[0].wdcapped))
                    {
                        console.log("INSIDE 00000");
                        superagentfee = parseFloat(terminal.rows[0].wdsharesa);
                        supersuper = parseFloat(terminal.rows[0].wdsharess)
                        tmsfee = (parseFloat(terminal.rows[0].wdcapped) - superagentfee - supersuper).toFixed(2);
                        cast = "NOT SETTLED";
                        if(parseFloat(superagentfee) <= 0)
                            sast = "SETTLED";
                        else
                            sast = "NOT SETTLED";
    
                        if(parseFloat(supersuper) <= 0)
                            ssst = "SETTLED";
                        else
                            ssst = "NOT SETTLED";
                    }else
                    {
                        console.log("OUTSIDE 00000");
                    }
                    agentamount = (parseFloat(amount) - parseFloat(tmsfee) - 
                        parseFloat(superagentfee) - parseFloat(supersuper)).toFixed(2);
                    
                    console.log(rrn);
                    var ml = "";
                    ml = rrn.toString();
                    var userrn = "20" + ml.slice(0, 2) + "-" + ml.slice(2, 4) + "-" + ml.slice(4, 6);
                    console.log("RRN: " + userrn);
                    var me = "SELECT * FROM walletactivies where tid = $1 AND amount = $2 AND tousedate = $3";
                    pool.query(me, [tid, agentamount, userrn], (err, wat) => {
                        if (err) 
                        {
                            return res.status(200).send({"status": 200, "message": "An Error Occurred. Not Successful."});
                        }else
                        {
                            if(wat.rows === undefined || wat.rows.length < 1)
                            {
                                if(1) 
                                {
                                    var qry2 = "INSERT INTO frometranzact " + 
                                        "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                        "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                        "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, stampduty, mainamount, fee, vatkar, varetzn, ref)" + 
                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36)";
                                    pool.query(qry2, ["", "", "", rrn, tid, "", "CASH WITHDRAWAL", terminal.rows[0].caaccountnumber, 
                                        terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                        terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, 
                                        terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, 
                                        rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                        terminal.rows[0].accountname, transRef, "DEBIT SUCCESS", amount, agentamount, superagentfee, 
                                        tmsfee, usemsc, terminal.rows[0].switchfee, "NA", "0.00", stamp, mainamount, fee, vatKar, supersuper, rrn], (err, resul) => {
                                        if (err) 
                                        {
                                            console.log(err);
                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                            res.status(200).send({"status": 200, "message": "Internal Error. Retry Later."});
                                        }else
                                        {
                                            var qry = "SELECT * FROM walletbalance WHERE tid = $1";
                                            pool.query(qry, [tid], (err, love) => { 
                                                if (err) 
                                                {
                                                    logger.info("Database connection error: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                    res.status(200).send({"status": 200, "message": "Transaction Failed."});
                                                }
                                                else
                                                {
                                                    var preBal = 0.00;
                                                    var newBal = 0.00;
                                                    if(love.rows === undefined || love.rows.length == 0)
                                                    {
                                                        preBal = 0.00;
                                                        newBal = agentamount;
                                                    }else
                                                    {    
                                                        preBal = love.rows[0].amount;
                                                        newBal = (parseFloat(agentamount) + parseFloat(love.rows[0].amount)).toFixed(2);
                                                    }
                                                    var waA = "INSERT INTO walletactivies " + 
                                                        "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                                                        "VALUES ($1, $2, $3, $4, $5, $6)";
                                                    pool.query(waA, [tid, agentamount, preBal, newBal, 
                                                        "CREDIT", "CASH WITHDRAWAL"], (err, resul) => {
                                                        if (err) 
                                                        {
                                                            logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                            return res.status(200).send({"status": 200, "message": "Transaction Failed."});
                                                        }else
                                                        {
                                                            if(love.rows === undefined || love.rows.length == 0)
                                                            {
                                                                var qry2 = "INSERT INTO walletbalance " + 
                                                                    "(tid, amount, accountname," +
                                                                        "accountbankcode, accountnumber, bankname, status, usertype, email) " + 
                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)";
                                                                pool.query(qry2, [tid, agentamount, terminal.rows[0].contactname, "NA",
                                                                "NA", "NA", "WALLET", 
                                                                    "AGENT", terminal.rows[0].email], (err, resul) => {
                                                                    if (err) 
                                                                    {
                                                                        logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                        res.status(200).send({"status": 200, "message": "Transaction Failed."});
                                                                    }else
                                                                    {
                                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype" +
                                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                        pool.query(qry3, [tid, "", superagentfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                            terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                                                            terminal.rows[0].saaccountname, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountnumber,
                                                                            terminal.rows[0].saaccountbank, sast, "superagent" + tid], (err, resul) => {
                                                                            if (err) 
                                                                            {
                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                res.status(200).send({"status": 200, "message": "Internal Error. Retry Later."});
                                                                            }else
                                                                            {
                                                                                var qry3 = "INSERT INTO agencyinstant " + 
                                                                                    "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                    "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype" +
                                                                                    ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                                pool.query(qry3, [tid, "", tmsfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                    terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                                                                    terminal.rows[0].caaccountname, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountnumber,
                                                                                    terminal.rows[0].caaccountbank, cast, "tms" + tid], (err, resul) => {
                                                                                    if (err) 
                                                                                    {
                                                                                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                        res.status(200).send({"status": 200, "message": "Internal Error. Retry Later."});
                                                                                    }else
                                                                                    {
                                                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype" +
                                                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                                        pool.query(qry3, [tid, "", supersuper, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                            terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                                                                            terminal.rows[0].superaccountname, terminal.rows[0].superaccountcode, 
                                                                                            terminal.rows[0].superaccountnumber,
                                                                                            terminal.rows[0].superbankname, ssst, "supersuper" + tid], (err, resul) => {
                                                                                            if (err) 
                                                                                            {
                                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                res.status(200).send({"status": 200, "message": "Internal Error. Retry Later."});
                                                                                            }else
                                                                                            {
                                                                                                logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                return res.status(200).send({"status": 200, "message": "Successfully Added."});
                                                                                            }
                                                                                        });
                                                                                    }
                                                                                });
                                                                            }
                                                                        });
                                                                    }
                                                                });
                                                            }else
                                                            {
                                                                var totAgentAmount = (parseFloat(agentamount) + parseFloat(love.rows[0].amount)).toFixed(2);
                                                                var qry2 =
                                                                    "UPDATE walletbalance SET amount = $1, accountname = $2, accountbankcode = $3," + 
                                                                    "accountnumber = $4, bankname = $5, status = $6, usertype = $7 WHERE tid = $8";
                                                                pool.query(qry2, [totAgentAmount, terminal.rows[0].contactname, "NA",
                                                                "NA", "NA", "WALLET", 
                                                                    "AGENT", tid], (err, resul) => {
                                                                    if (err) 
                                                                    {
                                                                        console.log(err)
                                                                        logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                        res.status(200).send({"status": 200, "message": "Transaction Failed."});
                                                                    }else
                                                                    {
                                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype" +
                                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                        pool.query(qry3, [tid, "", superagentfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                            terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                                                            terminal.rows[0].saaccountname, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountnumber,
                                                                            terminal.rows[0].saaccountbank, sast, "superagent" + tid], (err, resul) => {
                                                                            if (err) 
                                                                            {
                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                res.status(200).send({"status": 200, "message": "Internal Error. Retry Later."});
                                                                            }else
                                                                            {
                                                                                var qry3 = "INSERT INTO agencyinstant " + 
                                                                                    "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                    "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype" +
                                                                                    ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                                pool.query(qry3, [tid, "", tmsfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                    terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                                                                    terminal.rows[0].caaccountname, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountnumber,
                                                                                    terminal.rows[0].caaccountbank, cast, "tms" + tid], (err, resul) => {
                                                                                    if (err) 
                                                                                    {
                                                                                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                        res.status(200).send({"status": 200, "message": "Internal Error. Retry Later."});
                                                                                    }else
                                                                                    {
                                                                                        var qry3 = "INSERT INTO agencyinstant " + 
                                                                                            "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                            "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype" +
                                                                                            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                                        pool.query(qry3, [tid, "", supersuper, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                            terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                                                                            terminal.rows[0].superaccountname, terminal.rows[0].superaccountcode, 
                                                                                            terminal.rows[0].superaccountnumber,
                                                                                            terminal.rows[0].superbankname, ssst, "supersuper" + tid], (err, resul) => {
                                                                                            if (err) 
                                                                                            {
                                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                res.status(200).send({"status": 200, "message": "Internal Error. Retry Later."});
                                                                                            }else
                                                                                            {
                                                                                                logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                return res.status(200).send({"status": 200, "message": "Successfully Added."});
                                                                                            }
                                                                                        });
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
                                }
                            }else
                            {
                                return res.status(200).send({"status": 200, "message": "Cashout Already Treated"});
                            }
                        }
                    });
                }
            }
        });
    }
});


//DISABLED TAKE NOTE
//VALIDATION
router.get("/oldvalidationothers", function(req, res) 
{
    //return res.status(500).send({"status": 500, "message": "Disabled."});

    var destination = req.headers.destination;//Account Number or Card Number or Mobile Number
    var bankcode = req.headers.bankcode;//Only compulsory for account
    var hash = sha512('2148669665STP' + 'j.alamu@tmsng.com' + 'Damola2020#' + bankcode + destination);
    var txn = `<GetAccountInOtherBank>
                    <customerid>2148669665STP</customerid>
                    <username>j.alamu@tmsng.com</username>
                    <password>Damola2020#</password>
                    <accountnumber>` + destination + `</accountnumber>
                    <bankcode>` + bankcode + `</bankcode>
                    <hash>` + hash + `</hash>
                </GetAccountInOtherBank>`;
    var xml = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:fil="http://tempuri.org/GAPS_Uploader/FileUploader">
                    <soapenv:Header/>
                    <soapenv:Body>
                    <fil:GetAccountInOtherBank>
                        <!--Optional:-->
                        <fil:xmlString>
                                <![CDATA[`
                                 + txn +   
                                `]]>
                        </fil:xmlString>
                    </fil:GetAccountInOtherBank>
                    </soapenv:Body>
                </soapenv:Envelope>`;
    logger.info(xml);
    var clientServerOptions = {
        uri: wsdlURL,
        body: xml,
        method: 'POST',
        headers: {
            'Content-Type': 'text/xml;charset=UTF-8'
        }
    }
    request(clientServerOptions, function (error, response) {
        if(error)
        {
            logger.info("ERROR: " + error);
            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful"});
        }
        if(response)
        {
            logger.info(response.statusCode);
            logger.info("RESPONSE");
            if(response.statusCode == 200)
            {
                var dt = JSON.stringify(response.body);
                var stxn = dt.replace(/&lt;/g, '<');
                var fstxn = stxn.replace(/&gt;/g, '>');
                var n1 = fstxn.indexOf("<GetAccountInOtherBankResult>");
                var n2 = fstxn.indexOf("</GetAccountInOtherBankResult>");
                var fn = fstxn.slice(n1, n2 + 30);
                parseString(fn, {explicitArray: false}, function (err, result) {
                    if(err)
                    {
                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful 2x"});
                    }else
                    {
                        return res.header("Content-Type",'Application/json').status(200).send(JSON.stringify(result));
                    }
                });
            }else
                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful"});
        }
    });
});

function wisencrypt(plainText, keyBase64, ivBase64) {
    const cipher  = crypto.createCipheriv('aes-128-cbc', keyBase64, ivBase64);
    let encrypted = cipher.update(plainText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function wisdecrypt(messagebase64, keyBase64, ivBase64) {
    const decipher = crypto.createDecipheriv('aes-128-cbc', keyBase64, ivBase64);
    let decrypted  = decipher.update(messagebase64, 'hex');
    decrypted += decipher.final();
    return decrypted;
}

//CHANGE WHEN CUT OFF VALIDATION
var keyBase64 = "7h6bk2rFqX7nUa3i";
var ivBase64  = '2R6j72Xwa5fVAAAo';
router.get("/validationothers", function(req, res) 
{
    var destination = req.headers.destination;//Account Number or Card Number or Mobile Number
    var bankcode = req.headers.bankcode;//Only compulsory for account
    if(bankcode.length > 3)
    {
        var bk = bankcode.slice(0, 3);
        bankcode = bk;
    }
    var enc = new Object();
    enc.bankCode = bankcode;
    enc.accountNumber = destination;
    console.log("Pre Validation: " + JSON.stringify(enc));

    var plainText = JSON.stringify(enc);
    var cipherText = wisencrypt(plainText, keyBase64, ivBase64);
    
    var sendout = new Object();
    sendout.encRequest = cipherText;
    console.log("Post Validation: " + JSON.stringify(sendout));

    var clientServerOptions = {
        uri: "http://41.203.111.118:9091/thirdParty/FT/Service/api/interbank/nameEnquiry",
        body: JSON.stringify(sendout),
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    }
    request(clientServerOptions, function (error, response) {
        if(error)
        {
            logger.info("ERROR: " + error);
            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful"});
        }
        if(response)
        {
            logger.info(response.statusCode);
            logger.info("RESPONSE");
            logger.info(response.body);
            if(response.statusCode == 200)
            {
                var rResponse = JSON.parse(response.body);
                var decipherText = JSON.parse(wisdecrypt(rResponse.encResponse, keyBase64, ivBase64));
                logger.info(decipherText);
                if(decipherText.responseCode === "00")
                {
                    //var resp = `{"GetAccountInOtherBankResult": {"Response": {"CODE": "1000","ACCOUNTNAME": "` 
                    var resp = `{"GetAccountInOtherBankResult": {"Response": {"CODE": "1000","ACCOUNTNAME":"` 
                    + decipherText.accountName + `"}}}`;
                    //return res.header("Content-Type",'Application/json').status(200).send(resp);
                    return res.status(200).send(resp);
                }else
                {
                    var resp = `{"GetAccountInOtherBankResult": {"Response": {"CODE": "1000","ACCOUNTNAME": "` 
                    + decipherText.accountName + `"}}}`;
                    return res.header("Content-Type",'Application/json').status(500).send(resp);
                }
            }else
                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful"});
        }
    });
});

//DISABLED TAKE NOTE
//WALLET CASH IN
//GTB
router.get("/oldwalletcashin", function(req, res) 
{
    var tid = req.headers.tid;
    var bankcode = req.headers.bankcode;//Headquarters code
    var destination = req.headers.destination;//Customer Account
    var amount = req.headers.amount.replace(/,/g, '');
    var mainamount = req.headers.mainamount.replace(/,/g, '');
    var fee = req.headers.fee.replace(/,/g, '');
    var tmsfee = req.headers.tmsfee;
    var superagentfee = req.headers.superagentfee;
    var description = req.headers.description;
    var termRef = req.headers.rrn;
    var receivername = req.headers.receivername;
    var bankname = req.headers.bankname;
    var supersuperfee = req.headers.supersuperfee;

    logger.info("CASH IN");
    logger.info(req.headers);

    //return res.status(200).send({"status": 200, "message": "Disabled."});

    var rrn = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef1 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef2 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef3 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef4 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef5 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef6 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef7 = randomstring.generate({
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
                            var usemsc = 0.00;
                            var stamp = 0.00;
                            var supersuper = 0.00;
                            var vatKar = 0.00;
                            var etzn = 0.00;
                            var vatEtzn = 0.00;
                            var agentamount = 0.00;
                            var toCus = 0.00;
                            var Tfees = 0.00;
                            
                            supersuper = supersuperfee;

                            console.log("RULE END");
                            Tfees = (parseFloat(tmsfee) + 
                                    parseFloat(superagentfee) + parseFloat(supersuper)).toFixed(2);
                            toCus = amount; 
                            
                            var totAgentAmount = (parseFloat(love.rows[0].amount) - parseFloat(amount) - parseFloat(Tfees)).toFixed(2);
                            if(totAgentAmount < 0)
                            {
                                return res.status(500).send({"status": 500, "message": "Amount too high"});
                            }else
                            {
                                if(isNumber(amount) === false)
                                {
                                    console.log(req.headers);
                                    return res.status(500).send({"status": 500, "message": "Invalid Amount. Retry Later"});
                                }else
                                {
                                    var qry2 =
                                        "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                                    pool.query(qry2, [totAgentAmount, tid], (err, resul) => {
                                        if (err) 
                                        {
                                            return res.status(500).send({"status": 500, "message": "An Error Occurred..."});
                                        }else
                                        {
                                            console.log(supersuper);
                                            console.log(superagentfee);
                                            console.log(agentamount);
                                            console.log(toCus);
                                            //return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "FEES DOES NOT TALLY"});

                                            var preBal = 0.00;
                                            var newBal = 0.00;
                                            preBal = love.rows[0].amount;
                                            newBal = parseFloat(totAgentAmount);
                                            var waA = "INSERT INTO walletactivies " + 
                                                "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                                                "VALUES ($1, $2, $3, $4, $5, $6)";
                                            pool.query(waA, [tid, amount, preBal, newBal, 
                                                "DEBIT", "WALLET TRANSFER TO " + destination + ". NAME: " + receivername], (err, resul) => {
                                                if (err) 
                                                {
                                                    logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                    return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                }else
                                                {
                                                    if(1)
                                                    {
                                                        //var totalBulk = (parseFloat(tmsfee) + parseFloat(superagentfee) + parseFloat(toCus) + parseFloat(vatKar) + parseFloat(agentamount)).toFixed(2);
                                                        var custShare = `<transaction>
                                                                <amount>` + toCus + `</amount>
                                                                <paymentdate>` + processorTime() + `</paymentdate>
                                                                <reference>` + transRef4 + `</reference>
                                                                <remarks>CASH IN ` + description + "-" + tid + "-" + termRef + `</remarks>
                                                                <vendorcode>` + transRef4 + `</vendorcode>
                                                                <vendorname>`+ receivername +`</vendorname>
                                                                <vendoracctnumber>` + destination + `</vendoracctnumber>
                                                                <vendorbankcode>` + bankcode + `</vendorbankcode>
                                                            </transaction>`;

                                                        var txn = "<transactions>" + custShare + "</transactions>";
                                                        logger.info(txn);
                                                        var stxn = txn.replace(/</g, '&lt;');
                                                        var fstxn = stxn.replace(/>/g, '&gt;');
                                                        var hash = sha512(txn + '2148669665STP' + 'j.alamu@tmsng.com' + 'Damola2020#');
                                    
                                                        var xml = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:fil="http://tempuri.org/GAPS_Uploader/FileUploader">
                                                            <soapenv:Header/>
                                                            <soapenv:Body>
                                                            <fil:SingleTransfers>
                                                                <!--Optional:-->
                                                                <fil:xmlRequest><![CDATA[<SingleTransfers><transdetails>` + fstxn
                                                                    + `</transdetails>
                                                        <accesscode>2148669665STP</accesscode>
                                                        <username>j.alamu@tmsng.com</username>
                                                        <password>Damola2020#</password>
                                                        <hash>` + hash +
                                                        `</hash>
                                                        </SingleTransfers>]]></fil:xmlRequest>
                                                            </fil:SingleTransfers>
                                                            </soapenv:Body>
                                                        </soapenv:Envelope>`;
                                                        logger.info(xml);
                                                        var clientServerOptions = {
                                                            uri: wsdlURL,
                                                            body: xml,
                                                            method: 'POST',
                                                            headers: {
                                                                'Content-Type': 'text/xml;charset=UTF-8'
                                                            }
                                                        }
                                                        request(clientServerOptions, function (error, split) {
                                                            if(error)
                                                            {
                                                                logger.info(clientServerOptions);
                                                                logger.info("ERROR: " + error);
                                                                logger.info("SPLIT NOT SUCCESS");
                                                                return res.header("Content-Type",'Application/json').status(500).send(split);
                                                            }
                                                            if(split)
                                                            {
                                                                logger.info(split.statusCode);
                                                                logger.info("SPLIT SUCCESS");
                                                                logger.info(split.body);
                                                                var dt = JSON.stringify(split.body);
                                                                stxn = dt.replace(/&lt;/g, '<');
                                                                fstxn = stxn.replace(/&gt;/g, '>');
                                                                var n1 = fstxn.indexOf("<SingleTransfersResult>");
                                                                var n2 = fstxn.indexOf("</SingleTransfersResult>");
                                                                var fn = fstxn.slice(n1, n2 + 24);
                                                                parseString(fn, {explicitArray: false}, function (err, result) {
                                                                    if(err)
                                                                    {
                                                                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful 2x"});
                                                                    }else
                                                                    {
                                                                        if(JSON.stringify(result).indexOf("Transaction Successful") !== -1)
                                                                        {
                                                                            var qry2 = "INSERT INTO frometranzact " + 
                                                                                "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                                                                "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                                                                "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, stampduty, vatkar, varetzn, etranzactresponse, etranzactecho, mainamount, fee, ref, dump)" + 
                                                                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39)";
                                                                            pool.query(qry2, ["tms HOLDING", "tms HOLDING", "NA", transRef, tid, "NA", "CASH DEPOSIT / TRANSFER", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                                                                terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                                                terminal.rows[0].accountname, rrn, "DEBIT SUCCESS", amount, agentamount, superagentfee, tmsfee, usemsc, terminal.rows[0].switchfee, destination, toCus, stamp, vatKar, supersuper, "FILE SUCCESSFULLY UPLOADED", JSON.stringify(result), mainamount, fee, termRef, xml], (err, resul) => {
                                                                                if (err) 
                                                                                {
                                                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                }else
                                                                                {
                                                                                    var qry9 = "INSERT INTO requery " + 
                                                                                        "(message, response, accountname, accountcode, accountnumber, accountbank, ref, amount, status, tid) " + 
                                                                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";
                                                                                    pool.query(qry9, [xml, JSON.stringify(result), receivername, bankcode, 
                                                                                        destination, bankname, transRef4, toCus, "NOT VALIDATED", tid], (err, resul) => {
                                                                                        if (err) 
                                                                                        {
                                                                                            logger.info(err);
                                                                                            logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 5x");
                                                                                            logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                            return res.header("Content-Type",'Application/json').status(200).send(JSON.stringify(result));
                                                                                        }else
                                                                                        {
                                                                                            var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                            pool.query(qry3, [tid, "", superagentfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                terminal.rows[0].saaccountname, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountnumber,
                                                                                                terminal.rows[0].saaccountbank, "NOT SETTLED", "superagent"+tid, termRef], (err, resul) => {
                                                                                                if (err) 
                                                                                                {
                                                                                                    logger.info(err);
                                                                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                                }else
                                                                                                {
                                                                                                    var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                        "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                        "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                        ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                                    pool.query(qry3, [tid, "", tmsfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                        terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                        terminal.rows[0].caaccountname, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountnumber,
                                                                                                        terminal.rows[0].caaccountbank, "NOT SETTLED", "tms" + tid, termRef], (err, resul) => {
                                                                                                        if (err) 
                                                                                                        {
                                                                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                            res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                                        }else
                                                                                                        {
                                                                                                            var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                                "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                                "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                                ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                                            pool.query(qry3, [tid, "", supersuper, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                                terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                                terminal.rows[0].superaccountname, terminal.rows[0].superaccountcode, terminal.rows[0].superaccountnumber,
                                                                                                                terminal.rows[0].superbankname, "NOT SETTLED", "supersuper" + tid, termRef], (err, resul) => {
                                                                                                                if (err) 
                                                                                                                {
                                                                                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                                                }else
                                                                                                                {
                                                                                                                    var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                                        "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                                        "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                                        ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                                                    pool.query(qry3, [tid, "", toCus, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                                        terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                                        receivername, bankcode, destination,
                                                                                                                        bankname, "SETTLED", "cus" + tid, termRef], (err, resul) => {
                                                                                                                        if (err) 
                                                                                                                        {
                                                                                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                            res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                                                        }else
                                                                                                                        {
                                                                                                                            //Customer Settlement
                                                                                                                            var qry10 = "INSERT INTO agentsettlement " + 
                                                                                                                                "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                                                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                                                            pool.query(qry10, [tid, toCus, bankname, 
                                                                                                                                bankcode, receivername, 
                                                                                                                                destination, description + " - " + JSON.stringify(result), termRef], (err, resul) => {
                                                                                                                                if (err) 
                                                                                                                                {
                                                                                                                                    logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                                                                    logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                                    return res.header("Content-Type",'Application/json').status(200).send(JSON.stringify(result));
                                                                                                                                }else
                                                                                                                                {
                                                                                                                                    logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                                    return res.header("Content-Type",'Application/json').status(200).send(JSON.stringify(result));
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
                                                                        }else
                                                                        {      
                                                                            var qry = "SELECT * FROM walletbalance WHERE tid = $1";
                                                                            pool.query(qry, [tid], (err, love) => { 
                                                                                if (err) 
                                                                                {
                                                                                    var mailOptions = {
                                                                                        from: emailHeading, // sender address
                                                                                        to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                        replyTo: replyTo,
                                                                                        subject: "tms WALLET CASH IN FAILURE", // Subject line
                                                                                        text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                    };
                                                                                        
                                                                                    transporter.sendMail(mailOptions, function(error, info){
                                                                                        if (error) {
                                                                                            logger.info(error);
                                                                                        } else {
                                                                                            logger.info('Email sent: ' + info.response);
                                                                                        }
                                                                                    });
                                                                                    logger.info("Database connection error 1.: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                    res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                }
                                                                                else
                                                                                {
                                                                                    var refundAmount = (parseFloat(love.rows[0].amount) + parseFloat(amount) + parseFloat(Tfees)).toFixed(2);
                                                                                    var qry2 =
                                                                                        "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                                                                                    pool.query(qry2, [refundAmount, tid], (err, resul) => {
                                                                                        if (err) 
                                                                                        {
                                                                                            var mailOptions = {
                                                                                                from: emailHeading, // sender address
                                                                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                replyTo: replyTo,
                                                                                                subject: "tms WALLET CASH IN FAILURE", // Subject line
                                                                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                            };
                                                                                                
                                                                                            transporter.sendMail(mailOptions, function(error, info){
                                                                                                if (error) {
                                                                                                    logger.info(error);
                                                                                                } else {
                                                                                                    logger.info('Email sent: ' + info.response);
                                                                                                }
                                                                                            });
                                                                                            logger.info("Database connection error 2.: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                            return res.status(500).send({"status": 500, "message": "An Error Occurred..."});
                                                                                        }else
                                                                                        {
                                                                                            var preBal = 0.00;
                                                                                            var newBal = 0.00;
                                                                                            preBal = love.rows[0].amount;
                                                                                            newBal = parseFloat(refundAmount);
                                                                                            var waA = "INSERT INTO walletactivies " + 
                                                                                                "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                                                                                                "VALUES ($1, $2, $3, $4, $5, $6)";
                                                                                            pool.query(waA, [tid, amount, preBal, newBal, 
                                                                                                "CREDIT", "WALLET REVERSAL FOR TRANSFER TO " + destination + ". NAME: " + receivername], (err, resul) => {
                                                                                                if (err) 
                                                                                                {
                                                                                                    var mailOptions = {
                                                                                                        from: emailHeading, // sender address
                                                                                                        to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                        replyTo: replyTo,
                                                                                                        subject: "tms WALLET CASH IN FAILURE", // Subject line
                                                                                                        text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                    };
                                                                                                        
                                                                                                    transporter.sendMail(mailOptions, function(error, info){
                                                                                                        if (error) {
                                                                                                            logger.info(error);
                                                                                                        } else {
                                                                                                            logger.info('Email sent: ' + info.response);
                                                                                                        }
                                                                                                    });
                                                                                                    logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                    return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                                }else
                                                                                                {
                                                                                                    var qry3 = "INSERT INTO etranzactstatus " + 
                                                                                                        "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                                                                                                        "bankname, bankcode, accountnumber, status, transactiontype, tmsfee, superagentfee, ref)" + 
                                                                                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                                                    pool.query(qry3, [JSON.stringify(result), JSON.stringify(result), JSON.stringify(result), 
                                                                                                        JSON.stringify(result), tid, amount, toCus, "NA", 
                                                                                                        bankcode, destination, "ERROR OCCURRED", "CASH IN", tmsfee, superagentfee, transRef4], (err, resul) => {
                                                                                                        if (err) 
                                                                                                        {
                                                                                                            var mailOptions = {
                                                                                                                from: emailHeading, // sender address
                                                                                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                                replyTo: replyTo,
                                                                                                                subject: "tms WALLET CASH IN FAILURE", // Subject line
                                                                                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                            };
                                                                                                                
                                                                                                            transporter.sendMail(mailOptions, function(error, info){
                                                                                                                if (error) {
                                                                                                                    logger.info(error);
                                                                                                                } else {
                                                                                                                    logger.info('Email sent: ' + info.response);
                                                                                                                }
                                                                                                            });
                                                                                                            logger.info("Error: " + err + ". Time: " +  new Date().toLocaleString());
                                                                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                            return res.header("Content-Type",'Application/json').status(500).send(JSON.stringify(result));
                                                                                                        }else
                                                                                                        {
                                                                                                            var mailOptions = {
                                                                                                                from: emailHeading, // sender address
                                                                                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                                replyTo: replyTo,
                                                                                                                subject: "tms WALLET CASH IN FAILURE", // Subject line
                                                                                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                            };
                                                                                                                
                                                                                                            transporter.sendMail(mailOptions, function(error, info){
                                                                                                                if (error) {
                                                                                                                    logger.info(error);
                                                                                                                } else {
                                                                                                                    logger.info('Email sent: ' + info.response);
                                                                                                                }
                                                                                                            });
                                                                                                            return res.header("Content-Type",'Application/json').status(500).send(JSON.stringify(result));
                                                                                                        }
                                                                                                    });
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
                                                }
                                            });
                                        }
                                    });
                                }
                            }
                        }
                    }
                });
            }
        }
    });
});

//DELETE
//KEYSTONE
router.get("/walletcashin", function(req, res) 
{
    var tid = req.headers.tid;
    var bankcode = req.headers.bankcode;//Headquarters code
    var destination = req.headers.destination;//Customer Account
    var amount = req.headers.amount.replace(/,/g, '');
    var mainamount = req.headers.mainamount.replace(/,/g, '');
    var fee = req.headers.fee.replace(/,/g, '');
    var tmsfee = req.headers.tmsfee;
    var superagentfee = req.headers.superagentfee;
    var description = req.headers.description;
    //var termRef = req.headers.rrn;
    var receivername = req.headers.receivername;
    var bankname = req.headers.bankname;
    var supersuperfee = req.headers.supersuperfee;

    logger.info("CASH IN");
    logger.info(req.headers);

    if(bankcode.length > 3)
    {
        var bk = bankcode.slice(0, 3);
        bankcode = bk;
    }

    var rrn = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var termRef = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef2 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef3 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef4 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef5 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef6 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef7 = randomstring.generate({
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
                            var usemsc = 0.00;
                            var stamp = 0.00;
                            var supersuper = 0.00;
                            var vatKar = 0.00;
                            var etzn = 0.00;
                            var vatEtzn = 0.00;
                            var agentamount = 0.00;
                            var toCus = 0.00;
                            var Tfees = 0.00;
                            
                            supersuper = supersuperfee;

                            console.log("RULE END");
                            Tfees = (parseFloat(tmsfee) + 
                                    parseFloat(superagentfee) + parseFloat(supersuper)).toFixed(2);
                            toCus = amount; 
                            
                            var totAgentAmount = (parseFloat(love.rows[0].amount) - parseFloat(amount) - parseFloat(Tfees)).toFixed(2);
                            if(totAgentAmount < 0)
                            {
                                return res.status(500).send({"status": 500, "message": "Amount too high"});
                            }else
                            {
                                if(isNumber(amount) === false)
                                {
                                    console.log(req.headers);
                                    return res.status(500).send({"status": 500, "message": "Invalid Amount. Retry Later"});
                                }else
                                {
                                    var qry2 =
                                        "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                                    pool.query(qry2, [totAgentAmount, tid], (err, resul) => {
                                        if (err) 
                                        {
                                            return res.status(500).send({"status": 500, "message": "An Error Occurred..."});
                                        }else
                                        {
                                            console.log(supersuper);
                                            console.log(superagentfee);
                                            console.log(agentamount);
                                            console.log(toCus);
                                            //return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "FEES DOES NOT TALLY"});

                                            var preBal = 0.00;
                                            var newBal = 0.00;
                                            preBal = love.rows[0].amount;
                                            newBal = parseFloat(totAgentAmount);
                                            var waA = "INSERT INTO walletactivies " + 
                                                "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                                                "VALUES ($1, $2, $3, $4, $5, $6)";
                                            pool.query(waA, [tid, amount, preBal, newBal, 
                                                "DEBIT", "WALLET TRANSFER TO " + destination + ". NAME: " + receivername], (err, resul) => {
                                                if (err) 
                                                {
                                                    logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                    return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                }else
                                                {
                                                    var enc = new Object();
                                                    enc.bankCode = bankcode;
                                                    enc.accountNumber = destination;
                                                    console.log("Pre Validation: " + JSON.stringify(enc));

                                                    var plainText = JSON.stringify(enc);
                                                    var cipherText = wisencrypt(plainText, keyBase64, ivBase64);
                                                    
                                                    var sendout = new Object();
                                                    sendout.encRequest = cipherText;
                                                    console.log("Post Validation: " + JSON.stringify(sendout));

                                                    var clientServerOptions = {
                                                        uri: "http://41.203.111.118:9091/thirdParty/FT/Service/api/interbank/nameEnquiry",
                                                        body: JSON.stringify(sendout),
                                                        method: 'POST',
                                                        headers: {
                                                            'Content-Type': 'application/json'
                                                        }
                                                    }
                                                    request(clientServerOptions, function (error, response) {
                                                        if(error)
                                                        {
                                                            logger.info("ERROR: " + error);
                                                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful"});
                                                        }
                                                        if(response)
                                                        {
                                                            logger.info(response.statusCode);
                                                            logger.info("RESPONSE");
                                                            logger.info(response.body);
                                                            if(response.statusCode == 200)
                                                            {
                                                                var rResponse = JSON.parse(response.body);
                                                                var decipherText = JSON.parse(wisdecrypt(rResponse.encResponse, keyBase64, ivBase64));
                                                                logger.info(decipherText);
                                                                if(decipherText.responseCode === "00")
                                                                {
                                                                    receivername = decipherText.accountName;
                                                                    if(1)
                                                                    {
                                                                        var enc = new Object();
                                                                        enc.txnId = transRef4;
                                                                        enc.beneficiaryAccountNumber = destination;
                                                                        enc.beneficiaryAccountName = receivername;
                                                                        enc.destBankCode = bankcode;
                                                                        enc.amount = toCus;
                                                                        enc.fee = "10.00";
                                                                        enc.senderAccountNumber = "1007358176";
                                                                        enc.senderAccountName = "CREDIT ASSIST INVESTMENT LIMITED";
                                                                        enc.narration = description;
                                                                        console.log("Pre Validation: " + JSON.stringify(enc));
                                                                        var plainText = JSON.stringify(enc);
                                                                        var cipherText = wisencrypt(plainText, keyBase64, ivBase64);
                                                                        var sendout = new Object();
                                                                        sendout.encRequest = cipherText;
                                                                        console.log("Post Validation: " + JSON.stringify(sendout));
                                                                        var xml = JSON.stringify(sendout);

                                                                        var clientServerOptions = {
                                                                            uri: "http://41.203.111.118:9091/thirdParty/FT/Service/api/interbank/FT",
                                                                            body: JSON.stringify(sendout),
                                                                            method: 'POST',
                                                                            headers: {
                                                                                'Content-Type': 'application/json'
                                                                            }
                                                                        }
                                                                        request(clientServerOptions, function (error, response) {
                                                                            if(error)
                                                                            {
                                                                                console.log(clientServerOptions);
                                                                                logger.info("ERROR: " + error);
                                                                                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful"});
                                                                            }
                                                                            if(response)
                                                                            {
                                                                                logger.info(response.statusCode);
                                                                                logger.info("RESPONSE");
                                                                                logger.info(response.body);
                                                                                if(response.statusCode == 200 && response.body)
                                                                                {
                                                                                    var d = response.body.slice(0, 1);
                                                                                    if(d == '{' || d == '[')
                                                                                    {
                                                                                        var rResponse = JSON.parse(response.body);
                                                                                        var decipherText = JSON.parse(wisdecrypt(rResponse.encResponse, keyBase64, ivBase64));
                                                                                        logger.info(decipherText);
                                                                                        if(decipherText.responseCode === "00")
                                                                                        {
                                                                                            var result = JSON.stringify(decipherText);
                                                                                            var rt = `{"SingleTransfersResult": {"Response": {"Code": "1000","Message": "Transaction Successful"}}}`;
                                                                                            var qry2 = "INSERT INTO frometranzact " + 
                                                                                                "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                                                                                "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                                                                                "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, stampduty, vatkar, varetzn, etranzactresponse, etranzactecho, mainamount, fee, ref, dump)" + 
                                                                                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39)";
                                                                                            pool.query(qry2, ["tms HOLDING", "tms HOLDING", "NA", transRef, tid, "NA", "CASH DEPOSIT / TRANSFER", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                                                                                terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                                                                terminal.rows[0].accountname, rrn, "DEBIT SUCCESS", amount, agentamount, superagentfee, tmsfee, usemsc, terminal.rows[0].switchfee, destination, toCus, stamp, vatKar, supersuper, "FILE SUCCESSFULLY UPLOADED", JSON.stringify(result), mainamount, fee, termRef, xml], (err, resul) => {
                                                                                                if (err) 
                                                                                                {
                                                                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later 1x."});
                                                                                                }else
                                                                                                {
                                                                                                    var qry9 = "INSERT INTO requery " + 
                                                                                                        "(message, response, accountname, accountcode, accountnumber, accountbank, ref, amount, status, tid) " + 
                                                                                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";
                                                                                                    pool.query(qry9, [xml, JSON.stringify(result), receivername, bankcode, 
                                                                                                        destination, bankname, transRef4, toCus, "NOT VALIDATED", tid], (err, resul) => {
                                                                                                        if (err) 
                                                                                                        {
                                                                                                            logger.info(err);
                                                                                                            logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 5x");
                                                                                                            logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                            return res.header("Content-Type",'Application/json').status(200).send(rt);
                                                                                                        }else
                                                                                                        {
                                                                                                            var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                                "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                                "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                                ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                                            pool.query(qry3, [tid, "", superagentfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                                terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                                terminal.rows[0].saaccountname, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountnumber,
                                                                                                                terminal.rows[0].saaccountbank, "NOT SETTLED", "superagent"+tid, termRef], (err, resul) => {
                                                                                                                if (err) 
                                                                                                                {
                                                                                                                    logger.info(err);
                                                                                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later 2x."});
                                                                                                                }else
                                                                                                                {
                                                                                                                    var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                                        "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                                        "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                                        ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                                                    pool.query(qry3, [tid, "", tmsfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                                        terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                                        terminal.rows[0].caaccountname, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountnumber,
                                                                                                                        terminal.rows[0].caaccountbank, "NOT SETTLED", "tms" + tid, termRef], (err, resul) => {
                                                                                                                        if (err) 
                                                                                                                        {
                                                                                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                            res.status(500).send({"status": 500, "message": "Internal Error. Retry Later 3x."});
                                                                                                                        }else
                                                                                                                        {
                                                                                                                            var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                                                "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                                                "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                                                ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                                                            pool.query(qry3, [tid, "", supersuper, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                                                terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                                                terminal.rows[0].superaccountname, terminal.rows[0].superaccountcode, terminal.rows[0].superaccountnumber,
                                                                                                                                terminal.rows[0].superbankname, "NOT SETTLED", "supersuper" + tid, termRef], (err, resul) => {
                                                                                                                                if (err) 
                                                                                                                                {
                                                                                                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later 4x."});
                                                                                                                                }else
                                                                                                                                {
                                                                                                                                    var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                                                        "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                                                        "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                                                        ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                                                                    pool.query(qry3, [tid, "", toCus, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                                                        terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                                                        receivername, bankcode, destination,
                                                                                                                                        bankname, "SETTLED", "cus" + tid, termRef], (err, resul) => {
                                                                                                                                        if (err) 
                                                                                                                                        {
                                                                                                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                                            res.status(500).send({"status": 500, "message": "Internal Error. Retry Later 5x."});
                                                                                                                                        }else
                                                                                                                                        {
                                                                                                                                            //Customer Settlement
                                                                                                                                            var qry10 = "INSERT INTO agentsettlement " + 
                                                                                                                                                "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                                                                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                                                                            pool.query(qry10, [tid, toCus, bankname, 
                                                                                                                                                bankcode, receivername, 
                                                                                                                                                destination, description + " - " + JSON.stringify(result), termRef], (err, resul) => {
                                                                                                                                                if (err) 
                                                                                                                                                {
                                                                                                                                                    logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                                                                                    logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                                                    return res.header("Content-Type",'Application/json').status(200).send(rt);
                                                                                                                                                }else
                                                                                                                                                {
                                                                                                                                                    logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                                                    return res.header("Content-Type",'Application/json').status(200).send(rt);
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
                                                                                        }else
                                                                                        {
                                                                                            var result = JSON.stringify(decipherText);
                                                                                            var rt = `{"SingleTransfersResult": {"Response": {"Code": "1000","Message": "` +
                                                                                            decipherText.responseMessage + `"}}}`;
                                                                                            var qry = "SELECT * FROM walletbalance WHERE tid = $1";
                                                                                            pool.query(qry, [tid], (err, love) => { 
                                                                                                if (err) 
                                                                                                {
                                                                                                    var mailOptions = {
                                                                                                        from: emailHeading, // sender address
                                                                                                        to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                        replyTo: replyTo,
                                                                                                        subject: "tms WALLET CASH IN FAILURE", // Subject line
                                                                                                        text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                    };
                                                                                                        
                                                                                                    transporter.sendMail(mailOptions, function(error, info){
                                                                                                        if (error) {
                                                                                                            logger.info(error);
                                                                                                        } else {
                                                                                                            logger.info('Email sent: ' + info.response);
                                                                                                        }
                                                                                                    });
                                                                                                    logger.info("Database connection error 1.: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                    res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                                }
                                                                                                else
                                                                                                {
                                                                                                    var refundAmount = (parseFloat(love.rows[0].amount) + parseFloat(amount) + parseFloat(Tfees)).toFixed(2);
                                                                                                    var qry2 =
                                                                                                        "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                                                                                                    pool.query(qry2, [refundAmount, tid], (err, resul) => {
                                                                                                        if (err) 
                                                                                                        {
                                                                                                            var mailOptions = {
                                                                                                                from: emailHeading, // sender address
                                                                                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                                replyTo: replyTo,
                                                                                                                subject: "tms WALLET CASH IN FAILURE", // Subject line
                                                                                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                            };
                                                                                                                
                                                                                                            transporter.sendMail(mailOptions, function(error, info){
                                                                                                                if (error) {
                                                                                                                    logger.info(error);
                                                                                                                } else {
                                                                                                                    logger.info('Email sent: ' + info.response);
                                                                                                                }
                                                                                                            });
                                                                                                            logger.info("Database connection error 2.: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                            return res.status(500).send({"status": 500, "message": "An Error Occurred..."});
                                                                                                        }else
                                                                                                        {
                                                                                                            var preBal = 0.00;
                                                                                                            var newBal = 0.00;
                                                                                                            preBal = love.rows[0].amount;
                                                                                                            newBal = parseFloat(refundAmount);
                                                                                                            var waA = "INSERT INTO walletactivies " + 
                                                                                                                "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                                                                                                                "VALUES ($1, $2, $3, $4, $5, $6)";
                                                                                                            pool.query(waA, [tid, amount, preBal, newBal, 
                                                                                                                "CREDIT", "WALLET REVERSAL FOR TRANSFER TO " + destination + ". NAME: " + receivername], (err, resul) => {
                                                                                                                if (err) 
                                                                                                                {
                                                                                                                    var mailOptions = {
                                                                                                                        from: emailHeading, // sender address
                                                                                                                        to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                                        replyTo: replyTo,
                                                                                                                        subject: "tms WALLET CASH IN FAILURE", // Subject line
                                                                                                                        text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                                    };
                                                                                                                        
                                                                                                                    transporter.sendMail(mailOptions, function(error, info){
                                                                                                                        if (error) {
                                                                                                                            logger.info(error);
                                                                                                                        } else {
                                                                                                                            logger.info('Email sent: ' + info.response);
                                                                                                                        }
                                                                                                                    });
                                                                                                                    logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                    return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                                                }else
                                                                                                                {
                                                                                                                    var qry3 = "INSERT INTO etranzactstatus " + 
                                                                                                                        "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                                                                                                                        "bankname, bankcode, accountnumber, status, transactiontype, tmsfee, superagentfee, ref)" + 
                                                                                                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                                                                    pool.query(qry3, [JSON.stringify(result), JSON.stringify(result), JSON.stringify(result), 
                                                                                                                        JSON.stringify(result), tid, amount, toCus, "NA", 
                                                                                                                        bankcode, destination, "ERROR OCCURRED", "CASH IN", tmsfee, superagentfee, transRef4], (err, resul) => {
                                                                                                                        if (err) 
                                                                                                                        {
                                                                                                                            var mailOptions = {
                                                                                                                                from: emailHeading, // sender address
                                                                                                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                                                replyTo: replyTo,
                                                                                                                                subject: "tms WALLET CASH IN FAILURE", // Subject line
                                                                                                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                                            };
                                                                                                                                
                                                                                                                            transporter.sendMail(mailOptions, function(error, info){
                                                                                                                                if (error) {
                                                                                                                                    logger.info(error);
                                                                                                                                } else {
                                                                                                                                    logger.info('Email sent: ' + info.response);
                                                                                                                                }
                                                                                                                            });
                                                                                                                            logger.info("Error: " + err + ". Time: " +  new Date().toLocaleString());
                                                                                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                            return res.header("Content-Type",'Application/json').status(500).send(rt);
                                                                                                                        }else
                                                                                                                        {
                                                                                                                            var mailOptions = {
                                                                                                                                from: emailHeading, // sender address
                                                                                                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                                                replyTo: replyTo,
                                                                                                                                subject: "tms WALLET CASH IN FAILURE", // Subject line
                                                                                                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                                            };
                                                                                                                                
                                                                                                                            transporter.sendMail(mailOptions, function(error, info){
                                                                                                                                if (error) {
                                                                                                                                    logger.info(error);
                                                                                                                                } else {
                                                                                                                                    logger.info('Email sent: ' + info.response);
                                                                                                                                }
                                                                                                                            });
                                                                                                                            return res.header("Content-Type",'Application/json').status(500).send(rt);
                                                                                                                        }
                                                                                                                    });
                                                                                                                }
                                                                                                            });
                                                                                                        }
                                                                                                    });
                                                                                                }
                                                                                            });
                                                                                        }
                                                                                    }else
                                                                                    {
                                                                                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful 2x"});
                                                                                    }
                                                                                }else
                                                                                {
                                                                                    return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful"});
                                                                                }
                                                                            }
                                                                        });
                                                                    }
                                                                }else
                                                                {
                                                                    return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful"});
                                                                }
                                                            }else
                                                                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful"});
                                                        }
                                                    });
                                                }
                                            });
                                        }
                                    });
                                }
                            }
                        }
                    }
                });
            }
        }
    });
});

//KEYSTONE
router.get("/upwalletcashin", function(req, res) 
{
    var tid = req.headers.tid;
    var bankcode = req.headers.bankcode;//Headquarters code
    var destination = req.headers.destination;//Customer Account
    var amount = req.headers.amount.replace(/,/g, '');
    var mainamount = req.headers.mainamount.replace(/,/g, '');
    var fee = req.headers.fee.replace(/,/g, '');
    var tmsfee = req.headers.tmsfee;
    var superagentfee = req.headers.superagentfee;
    var description = req.headers.description;
    //var termRef = req.headers.rrn;
    var receivername = req.headers.receivername;
    var bankname = req.headers.bankname;
    var supersuperfee = req.headers.supersuperfee;

    logger.info("CASH IN");
    logger.info(req.headers);

    if(bankcode.length > 3)
    {
        var bk = bankcode.slice(0, 3);
        bankcode = bk;
    }

    var rrn = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var termRef = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef2 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef3 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef4 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef5 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef6 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef7 = randomstring.generate({
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
                            var usemsc = 0.00;
                            var stamp = 0.00;
                            var supersuper = 0.00;
                            var vatKar = 0.00;
                            var etzn = 0.00;
                            var vatEtzn = 0.00;
                            var agentamount = 0.00;
                            var toCus = 0.00;
                            var Tfees = 0.00;
                            
                            supersuper = supersuperfee;

                            console.log("RULE END");
                            Tfees = (parseFloat(tmsfee) + 
                                    parseFloat(superagentfee) + parseFloat(supersuper)).toFixed(2);
                            toCus = amount; 
                            
                            var totAgentAmount = (parseFloat(love.rows[0].amount) - parseFloat(amount) - parseFloat(Tfees)).toFixed(2);
                            if(totAgentAmount < 0)
                            {
                                return res.status(500).send({"status": 500, "message": "Amount too high"});
                            }else
                            {
                                if(isNumber(amount) === false)
                                {
                                    console.log(req.headers);
                                    return res.status(500).send({"status": 500, "message": "Invalid Amount. Retry Later"});
                                }else
                                {
                                    var qry2 =
                                        "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                                    pool.query(qry2, [totAgentAmount, tid], (err, resul) => {
                                        if (err) 
                                        {
                                            return res.status(500).send({"status": 500, "message": "An Error Occurred..."});
                                        }else
                                        {
                                            console.log(supersuper);
                                            console.log(superagentfee);
                                            console.log(agentamount);
                                            console.log(toCus);
                                            //return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "FEES DOES NOT TALLY"});

                                            var preBal = 0.00;
                                            var newBal = 0.00;
                                            preBal = love.rows[0].amount;
                                            newBal = parseFloat(totAgentAmount);
                                            var waA = "INSERT INTO walletactivies " + 
                                                "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                                                "VALUES ($1, $2, $3, $4, $5, $6)";
                                            pool.query(waA, [tid, amount, preBal, newBal, 
                                                "DEBIT", "WALLET TRANSFER TO " + destination + ". NAME: " + receivername], (err, resul) => {
                                                if (err) 
                                                {
                                                    logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                    return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                }else
                                                {
                                                    var enc = new Object();
                                                    enc.bankCode = bankcode;
                                                    enc.accountNumber = destination;
                                                    console.log("Pre Validation: " + JSON.stringify(enc));

                                                    var plainText = JSON.stringify(enc);
                                                    var cipherText = wisencrypt(plainText, keyBase64, ivBase64);
                                                    
                                                    var sendout = new Object();
                                                    sendout.encRequest = cipherText;
                                                    console.log("Post Validation: " + JSON.stringify(sendout));

                                                    var clientServerOptions = {
                                                        uri: "http://41.203.111.118:9091/thirdParty/FT/Service/api/interbank/nameEnquiry",
                                                        body: JSON.stringify(sendout),
                                                        method: 'POST',
                                                        headers: {
                                                            'Content-Type': 'application/json'
                                                        }
                                                    }
                                                    request(clientServerOptions, function (error, response) {
                                                        if(error)
                                                        {
                                                            logger.info("ERROR: " + error);
                                                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful"});
                                                        }
                                                        if(response)
                                                        {
                                                            logger.info(response.statusCode);
                                                            logger.info("RESPONSE");
                                                            logger.info(response.body);
                                                            if(response.statusCode == 200)
                                                            {
                                                                var rResponse = JSON.parse(response.body);
                                                                var decipherText = JSON.parse(wisdecrypt(rResponse.encResponse, keyBase64, ivBase64));
                                                                logger.info(decipherText);
                                                                if(decipherText.responseCode === "00")
                                                                {
                                                                    receivername = decipherText.accountName;
                                                                    if(1)
                                                                    {
                                                                        var enc = new Object();
                                                                        enc.txnId = transRef4;
                                                                        enc.beneficiaryAccountNumber = destination;
                                                                        enc.beneficiaryAccountName = receivername;
                                                                        enc.destBankCode = bankcode;
                                                                        enc.amount = toCus;
                                                                        enc.fee = "10.00";
                                                                        enc.senderAccountNumber = "1007358176";
                                                                        enc.senderAccountName = "CREDIT ASSIST INVESTMENT LIMITED";
                                                                        enc.narration = description;
                                                                        console.log("Pre Validation: " + JSON.stringify(enc));
                                                                        var plainText = JSON.stringify(enc);
                                                                        var cipherText = wisencrypt(plainText, keyBase64, ivBase64);
                                                                        var sendout = new Object();
                                                                        sendout.encRequest = cipherText;
                                                                        console.log("Post Validation: " + JSON.stringify(sendout));
                                                                        var xml = JSON.stringify(sendout);

                                                                        var clientServerOptions = {
                                                                            uri: "http://41.203.111.118:9091/thirdParty/FT/Service/api/interbank/FT",
                                                                            body: JSON.stringify(sendout),
                                                                            method: 'POST',
                                                                            headers: {
                                                                                'Content-Type': 'application/json'
                                                                            }
                                                                        }
                                                                        request(clientServerOptions, function (error, response) {
                                                                            if(error)
                                                                            {
                                                                                console.log(clientServerOptions);
                                                                                logger.info("ERROR: " + error);
                                                                                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful"});
                                                                            }
                                                                            if(response)
                                                                            {
                                                                                logger.info(response.statusCode);
                                                                                logger.info("RESPONSE");
                                                                                logger.info(response.body);
                                                                                if(response.statusCode == 200 && response.body)
                                                                                {
                                                                                    var d = response.body.slice(0, 1);
                                                                                    if(d == '{' || d == '[')
                                                                                    {
                                                                                        var rResponse = JSON.parse(response.body);
                                                                                        var decipherText = JSON.parse(wisdecrypt(rResponse.encResponse, keyBase64, ivBase64));
                                                                                        logger.info(decipherText);
                                                                                        if(decipherText.responseCode === "00")
                                                                                        {
                                                                                            var result = JSON.stringify(decipherText);
                                                                                            var rt = `{"SingleTransfersResult": {"Response": {"Code": "1000","Message": "Transaction Successful"}}}`;
                                                                                            var qry2 = "INSERT INTO frometranzact " + 
                                                                                                "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                                                                                "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                                                                                "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, stampduty, vatkar, varetzn, etranzactresponse, etranzactecho, mainamount, fee, ref, dump)" + 
                                                                                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39)";
                                                                                            pool.query(qry2, ["tms HOLDING", "tms HOLDING", "NA", transRef, tid, "NA", "CASH DEPOSIT / TRANSFER", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                                                                                terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                                                                terminal.rows[0].accountname, rrn, "DEBIT SUCCESS", amount, agentamount, superagentfee, tmsfee, usemsc, terminal.rows[0].switchfee, destination, toCus, stamp, vatKar, supersuper, "FILE SUCCESSFULLY UPLOADED", JSON.stringify(result), mainamount, fee, termRef, xml], (err, resul) => {
                                                                                                if (err) 
                                                                                                {
                                                                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later 1x."});
                                                                                                }else
                                                                                                {
                                                                                                    var qry9 = "INSERT INTO requery " + 
                                                                                                        "(message, response, accountname, accountcode, accountnumber, accountbank, ref, amount, status, tid) " + 
                                                                                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";
                                                                                                    pool.query(qry9, [xml, JSON.stringify(result), receivername, bankcode, 
                                                                                                        destination, bankname, transRef4, toCus, "NOT VALIDATED", tid], (err, resul) => {
                                                                                                        if (err) 
                                                                                                        {
                                                                                                            logger.info(err);
                                                                                                            logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 5x");
                                                                                                            logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                            return res.header("Content-Type",'Application/json').status(200).send(rt);
                                                                                                        }else
                                                                                                        {
                                                                                                            var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                                "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                                "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                                ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                                            pool.query(qry3, [tid, "", superagentfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                                terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                                terminal.rows[0].saaccountname, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountnumber,
                                                                                                                terminal.rows[0].saaccountbank, "NOT SETTLED", "superagent"+tid, termRef], (err, resul) => {
                                                                                                                if (err) 
                                                                                                                {
                                                                                                                    logger.info(err);
                                                                                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later 2x."});
                                                                                                                }else
                                                                                                                {
                                                                                                                    var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                                        "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                                        "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                                        ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                                                    pool.query(qry3, [tid, "", tmsfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                                        terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                                        terminal.rows[0].caaccountname, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountnumber,
                                                                                                                        terminal.rows[0].caaccountbank, "NOT SETTLED", "tms" + tid, termRef], (err, resul) => {
                                                                                                                        if (err) 
                                                                                                                        {
                                                                                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                            res.status(500).send({"status": 500, "message": "Internal Error. Retry Later 3x."});
                                                                                                                        }else
                                                                                                                        {
                                                                                                                            var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                                                "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                                                "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                                                ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                                                            pool.query(qry3, [tid, "", supersuper, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                                                terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                                                terminal.rows[0].superaccountname, terminal.rows[0].superaccountcode, terminal.rows[0].superaccountnumber,
                                                                                                                                terminal.rows[0].superbankname, "NOT SETTLED", "supersuper" + tid, termRef], (err, resul) => {
                                                                                                                                if (err) 
                                                                                                                                {
                                                                                                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later 4x."});
                                                                                                                                }else
                                                                                                                                {
                                                                                                                                    var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                                                        "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                                                        "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                                                        ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                                                                    pool.query(qry3, [tid, "", toCus, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                                                        terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                                                        receivername, bankcode, destination,
                                                                                                                                        bankname, "SETTLED", "cus" + tid, termRef], (err, resul) => {
                                                                                                                                        if (err) 
                                                                                                                                        {
                                                                                                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                                            res.status(500).send({"status": 500, "message": "Internal Error. Retry Later 5x."});
                                                                                                                                        }else
                                                                                                                                        {
                                                                                                                                            //Customer Settlement
                                                                                                                                            var qry10 = "INSERT INTO agentsettlement " + 
                                                                                                                                                "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                                                                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                                                                            pool.query(qry10, [tid, toCus, bankname, 
                                                                                                                                                bankcode, receivername, 
                                                                                                                                                destination, description + " - " + JSON.stringify(result), termRef], (err, resul) => {
                                                                                                                                                if (err) 
                                                                                                                                                {
                                                                                                                                                    logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                                                                                    logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                                                    return res.header("Content-Type",'Application/json').status(200).send(rt);
                                                                                                                                                }else
                                                                                                                                                {
                                                                                                                                                    logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                                                    return res.header("Content-Type",'Application/json').status(200).send(rt);
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
                                                                                        }else
                                                                                        {
                                                                                            var result = JSON.stringify(decipherText);
                                                                                            var rt = `{"SingleTransfersResult": {"Response": {"Code": "1000","Message": "` +
                                                                                            decipherText.responseMessage + `"}}}`;
                                                                                            var qry = "SELECT * FROM walletbalance WHERE tid = $1";
                                                                                            pool.query(qry, [tid], (err, love) => { 
                                                                                                if (err) 
                                                                                                {
                                                                                                    var mailOptions = {
                                                                                                        from: emailHeading, // sender address
                                                                                                        to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                        replyTo: replyTo,
                                                                                                        subject: "tms WALLET CASH IN FAILURE", // Subject line
                                                                                                        text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                    };
                                                                                                        
                                                                                                    transporter.sendMail(mailOptions, function(error, info){
                                                                                                        if (error) {
                                                                                                            logger.info(error);
                                                                                                        } else {
                                                                                                            logger.info('Email sent: ' + info.response);
                                                                                                        }
                                                                                                    });
                                                                                                    logger.info("Database connection error 1.: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                    res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                                }
                                                                                                else
                                                                                                {
                                                                                                    var refundAmount = (parseFloat(love.rows[0].amount) + parseFloat(amount) + parseFloat(Tfees)).toFixed(2);
                                                                                                    var qry2 =
                                                                                                        "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                                                                                                    pool.query(qry2, [refundAmount, tid], (err, resul) => {
                                                                                                        if (err) 
                                                                                                        {
                                                                                                            var mailOptions = {
                                                                                                                from: emailHeading, // sender address
                                                                                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                                replyTo: replyTo,
                                                                                                                subject: "tms WALLET CASH IN FAILURE", // Subject line
                                                                                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                            };
                                                                                                                
                                                                                                            transporter.sendMail(mailOptions, function(error, info){
                                                                                                                if (error) {
                                                                                                                    logger.info(error);
                                                                                                                } else {
                                                                                                                    logger.info('Email sent: ' + info.response);
                                                                                                                }
                                                                                                            });
                                                                                                            logger.info("Database connection error 2.: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                            return res.status(500).send({"status": 500, "message": "An Error Occurred..."});
                                                                                                        }else
                                                                                                        {
                                                                                                            var preBal = 0.00;
                                                                                                            var newBal = 0.00;
                                                                                                            preBal = love.rows[0].amount;
                                                                                                            newBal = parseFloat(refundAmount);
                                                                                                            var waA = "INSERT INTO walletactivies " + 
                                                                                                                "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                                                                                                                "VALUES ($1, $2, $3, $4, $5, $6)";
                                                                                                            pool.query(waA, [tid, amount, preBal, newBal, 
                                                                                                                "CREDIT", "WALLET REVERSAL FOR TRANSFER TO " + destination + ". NAME: " + receivername], (err, resul) => {
                                                                                                                if (err) 
                                                                                                                {
                                                                                                                    var mailOptions = {
                                                                                                                        from: emailHeading, // sender address
                                                                                                                        to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                                        replyTo: replyTo,
                                                                                                                        subject: "tms WALLET CASH IN FAILURE", // Subject line
                                                                                                                        text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                                    };
                                                                                                                        
                                                                                                                    transporter.sendMail(mailOptions, function(error, info){
                                                                                                                        if (error) {
                                                                                                                            logger.info(error);
                                                                                                                        } else {
                                                                                                                            logger.info('Email sent: ' + info.response);
                                                                                                                        }
                                                                                                                    });
                                                                                                                    logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                    return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                                                }else
                                                                                                                {
                                                                                                                    var qry3 = "INSERT INTO etranzactstatus " + 
                                                                                                                        "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                                                                                                                        "bankname, bankcode, accountnumber, status, transactiontype, tmsfee, superagentfee, ref)" + 
                                                                                                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                                                                    pool.query(qry3, [JSON.stringify(result), JSON.stringify(result), JSON.stringify(result), 
                                                                                                                        JSON.stringify(result), tid, amount, toCus, "NA", 
                                                                                                                        bankcode, destination, "ERROR OCCURRED", "CASH IN", tmsfee, superagentfee, transRef4], (err, resul) => {
                                                                                                                        if (err) 
                                                                                                                        {
                                                                                                                            var mailOptions = {
                                                                                                                                from: emailHeading, // sender address
                                                                                                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                                                replyTo: replyTo,
                                                                                                                                subject: "tms WALLET CASH IN FAILURE", // Subject line
                                                                                                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                                            };
                                                                                                                                
                                                                                                                            transporter.sendMail(mailOptions, function(error, info){
                                                                                                                                if (error) {
                                                                                                                                    logger.info(error);
                                                                                                                                } else {
                                                                                                                                    logger.info('Email sent: ' + info.response);
                                                                                                                                }
                                                                                                                            });
                                                                                                                            logger.info("Error: " + err + ". Time: " +  new Date().toLocaleString());
                                                                                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                            return res.header("Content-Type",'Application/json').status(500).send(rt);
                                                                                                                        }else
                                                                                                                        {
                                                                                                                            var mailOptions = {
                                                                                                                                from: emailHeading, // sender address
                                                                                                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                                                replyTo: replyTo,
                                                                                                                                subject: "tms WALLET CASH IN FAILURE", // Subject line
                                                                                                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                                            };
                                                                                                                                
                                                                                                                            transporter.sendMail(mailOptions, function(error, info){
                                                                                                                                if (error) {
                                                                                                                                    logger.info(error);
                                                                                                                                } else {
                                                                                                                                    logger.info('Email sent: ' + info.response);
                                                                                                                                }
                                                                                                                            });
                                                                                                                            return res.header("Content-Type",'Application/json').status(500).send(rt);
                                                                                                                        }
                                                                                                                    });
                                                                                                                }
                                                                                                            });
                                                                                                        }
                                                                                                    });
                                                                                                }
                                                                                            });
                                                                                        }
                                                                                    }else
                                                                                    {
                                                                                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful 2x"});
                                                                                    }
                                                                                }else
                                                                                {
                                                                                    return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful"});
                                                                                }
                                                                            }
                                                                        });
                                                                    }
                                                                }else
                                                                {
                                                                    return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful"});
                                                                }
                                                            }else
                                                                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful"});
                                                        }
                                                    });
                                                }
                                            });
                                        }
                                    });
                                }
                            }
                        }
                    }
                });
            }
        }
    });
});

//DELETE
//CARD CASH IN
//GTB
router.get("/oldcashin", function(req, res) 
{
    var tid = req.headers.tid;
    var bankcode = req.headers.bankcode;//Headquarters code
    var destination = req.headers.destination;//Customer Account
    var amount = req.headers.amount.replace(/,/g, '');
    var mainamount = req.headers.mainamount.replace(/,/g, '');
    var fee = req.headers.fee.replace(/,/g, '');
    var tmsfee = req.headers.tmsfee;
    var superagentfee = req.headers.superagentfee;
    var description = req.headers.description;
    var termRef = req.headers.rrn;
    var receivername = req.headers.receivername;
    var bankname = req.headers.bankname;
    var supersuperfee = req.headers.supersuperfee;

    logger.info("CASH IN WALLET");
    logger.info(req.headers);

    //return res.status(200).send({"status": 200, "message": "Disabled."});

    var rrn = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef1 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef2 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef3 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef4 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef5 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef6 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef7 = randomstring.generate({
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
                            var supersuper = 0.00;
                            var vatKar = 0.00;
                            var etzn = 0.00;
                            var vatEtzn = 0.00;
                            var agentamount = 0.00;
                            var toCus = 0.00;
                            var Tfees = 0.00;
            
                            tmsfee = parseFloat(terminal.rows[0].cttms);
                            superagentfee = parseFloat(terminal.rows[0].ctsuperagent);
                            supersuperfee = parseFloat(terminal.rows[0].ctsupersuperagent);
                            supersuper = superagentfee;
                            var usemsc = 0.00;
                            var stamp = 0.00;
                            Tfees = (parseFloat(tmsfee) + 
                                    parseFloat(superagentfee) + parseFloat(supersuperfee)).toFixed(2);
                            toCus = amount;
                            
                            var totAgentAmount = (parseFloat(love.rows[0].amount) - parseFloat(Tfees)).toFixed(2);
                            if(totAgentAmount < 0)
                            {
                                return res.status(500).send({"status": 500, "message": "Amount too high"});
                            }else
                            {
                                if(isNumber(amount) === false)
                                {
                                    console.log(req.headers);
                                    return res.status(500).send({"status": 500, "message": "Invalid Amount. Retry Later"});
                                }else
                                {
                                    var qry2 =
                                        "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                                    pool.query(qry2, [totAgentAmount, tid], (err, resul) => {
                                        if (err) 
                                        {
                                            return res.status(500).send({"status": 500, "message": "An Error Occurred..."});
                                        }else
                                        {
                                            console.log(supersuper);
                                            console.log(tmsfee);
                                            console.log(superagentfee);
                                            console.log(toCus);
                                            //return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "FEES DOES NOT TALLY"});
                                            var preBal = 0.00;
                                            var newBal = 0.00;
                                            preBal = love.rows[0].amount;
                                            newBal = parseFloat(totAgentAmount);
                                            var waA = "INSERT INTO walletactivies " + 
                                                "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                                                "VALUES ($1, $2, $3, $4, $5, $6)";
                                            pool.query(waA, [tid, amount, preBal, newBal, 
                                                "DEBIT", "CARD TRANSFER TO " + destination + ". NAME: " + receivername], (err, resul) => {
                                                if (err) 
                                                {
                                                    logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                    return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                }else
                                                {
                                                    if(1)
                                                    {
                                                        var custShare = `<transaction>
                                                                <amount>` + toCus + `</amount>
                                                                <paymentdate>` + processorTime() + `</paymentdate>
                                                                <reference>` + transRef4 + `</reference>
                                                                <remarks>CASH IN ` + description + "-" + tid + "-" + termRef + `</remarks>
                                                                <vendorcode>` + transRef4 + `</vendorcode>
                                                                <vendorname>`+ receivername +`</vendorname>
                                                                <vendoracctnumber>` + destination + `</vendoracctnumber>
                                                                <vendorbankcode>` + bankcode + `</vendorbankcode>
                                                            </transaction>`;
                                                        var txn = "<transactions>" + custShare + "</transactions>";
                                                        logger.info(txn);
                                                        var stxn = txn.replace(/</g, '&lt;');
                                                        var fstxn = stxn.replace(/>/g, '&gt;');
                                                        var hash = sha512(txn + '2148669665STP' + 'j.alamu@tmsng.com' + 'Damola2020#');
                                    
                                                        var xml = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:fil="http://tempuri.org/GAPS_Uploader/FileUploader">
                                                            <soapenv:Header/>
                                                            <soapenv:Body>
                                                            <fil:SingleTransfers>
                                                                <!--Optional:-->
                                                                <fil:xmlRequest><![CDATA[<SingleTransfers><transdetails>` + fstxn
                                                                    + `</transdetails>
                                                        <accesscode>2148669665STP</accesscode>
                                                        <username>j.alamu@tmsng.com</username>
                                                        <password>Damola2020#</password>
                                                        <hash>` + hash +
                                                        `</hash>
                                                        </SingleTransfers>]]></fil:xmlRequest>
                                                            </fil:SingleTransfers>
                                                            </soapenv:Body>
                                                        </soapenv:Envelope>`;
                                                        logger.info(xml);
                                                        var clientServerOptions = {
                                                            uri: wsdlURL,
                                                            body: xml,
                                                            method: 'POST',
                                                            headers: {
                                                                'Content-Type': 'text/xml;charset=UTF-8'
                                                            }
                                                        }
                                                        request(clientServerOptions, function (error, split) {
                                                            if(error)
                                                            {
                                                                logger.info(clientServerOptions);
                                                                logger.info("ERROR: " + error);
                                                                logger.info("SPLIT NOT SUCCESS");
                                                                return res.header("Content-Type",'Application/json').status(500).send(split);
                                                            }
                                                            if(split)
                                                            {
                                                                logger.info(split.statusCode);
                                                                logger.info("SPLIT SUCCESS");
                                                                logger.info(split.body);
                                                                var dt = JSON.stringify(split.body);
                                                                stxn = dt.replace(/&lt;/g, '<');
                                                                fstxn = stxn.replace(/&gt;/g, '>');
                                                                var n1 = fstxn.indexOf("<SingleTransfersResult>");
                                                                var n2 = fstxn.indexOf("</SingleTransfersResult>");
                                                                var fn = fstxn.slice(n1, n2 + 24);
                                                                parseString(fn, {explicitArray: false}, function (err, result) {
                                                                    if(err)
                                                                    {
                                                                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful 2x"});
                                                                    }else
                                                                    {
                                                                        if(JSON.stringify(result).indexOf("Transaction Successful") !== -1)
                                                                        {
                                                                            var qry2 = "INSERT INTO frometranzact " + 
                                                                                "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                                                                "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                                                                "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, stampduty, vatkar, varetzn, etranzactresponse, etranzactecho, mainamount, fee, ref, dump)" + 
                                                                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39)";
                                                                            pool.query(qry2, ["tms HOLDING", "tms HOLDING", "NA", transRef, tid, "NA", "CASH DEPOSIT / TRANSFER", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                                                                terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                                                terminal.rows[0].accountname, rrn, "Transaction Success - CARD", amount, agentamount, superagentfee, tmsfee, usemsc, terminal.rows[0].switchfee, destination, toCus, stamp, vatKar, supersuper, "FILE SUCCESSFULLY UPLOADED", JSON.stringify(result), mainamount, fee, termRef, xml], (err, resul) => {
                                                                                if (err) 
                                                                                {
                                                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                }else
                                                                                {
                                                                                    var qry9 = "INSERT INTO requery " + 
                                                                                        "(message, response, accountname, accountcode, accountnumber, accountbank, ref, amount, status, tid) " + 
                                                                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";
                                                                                    pool.query(qry9, [xml, JSON.stringify(result), receivername, bankcode, 
                                                                                        destination, bankname, transRef4, toCus, "NOT VALIDATED", tid], (err, resul) => {
                                                                                        if (err) 
                                                                                        {
                                                                                            logger.info(err);
                                                                                            logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 5x");
                                                                                            logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                            return res.header("Content-Type",'Application/json').status(200).send(JSON.stringify(result));
                                                                                        }else
                                                                                        {
                                                                                            var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                            pool.query(qry3, [tid, "", superagentfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                terminal.rows[0].saaccountname, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountnumber,
                                                                                                terminal.rows[0].saaccountbank, "NOT SETTLED", "superagent"+tid, termRef], (err, resul) => {
                                                                                                if (err) 
                                                                                                {
                                                                                                    logger.info(err);
                                                                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                                }else
                                                                                                {
                                                                                                    var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                        "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                        "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                        ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                                    pool.query(qry3, [tid, "", tmsfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                        terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                        terminal.rows[0].caaccountname, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountnumber,
                                                                                                        terminal.rows[0].caaccountbank, "NOT SETTLED", "tms" + tid, termRef], (err, resul) => {
                                                                                                        if (err) 
                                                                                                        {
                                                                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                            res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                                        }else
                                                                                                        {
                                                                                                            var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                                "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                                "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                                ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                                            pool.query(qry3, [tid, "", supersuper, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                                terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                                terminal.rows[0].superaccountname, terminal.rows[0].superaccountcode, terminal.rows[0].superaccountnumber,
                                                                                                                terminal.rows[0].superbankname, "NOT SETTLED", "supersuper" + tid, termRef], (err, resul) => {
                                                                                                                if (err) 
                                                                                                                {
                                                                                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                                                }else
                                                                                                                {
                                                                                                                    var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                                        "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                                        "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                                        ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                                                    pool.query(qry3, [tid, "", toCus, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                                        terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                                        receivername, bankcode, destination,
                                                                                                                        bankname, "SETTLED", "cus" + tid, termRef], (err, resul) => {
                                                                                                                        if (err) 
                                                                                                                        {
                                                                                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                            res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                                                        }else
                                                                                                                        {
                                                                                                                            //Customer Settlement
                                                                                                                            var qry10 = "INSERT INTO agentsettlement " + 
                                                                                                                                "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                                                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                                                            pool.query(qry10, [tid, toCus, bankname, 
                                                                                                                                bankcode, receivername, 
                                                                                                                                destination, description + " - " + JSON.stringify(result), termRef], (err, resul) => {
                                                                                                                                if (err) 
                                                                                                                                {
                                                                                                                                    logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                                                                    logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                                    return res.header("Content-Type",'Application/json').status(200).send(JSON.stringify(result));
                                                                                                                                }else
                                                                                                                                {
                                                                                                                                    logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                                    return res.header("Content-Type",'Application/json').status(200).send(JSON.stringify(result));
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
                                                                        }else
                                                                        {  
                                                                            var qry = "SELECT * FROM walletbalance WHERE tid = $1";
                                                                            pool.query(qry, [tid], (err, love) => { 
                                                                                if (err) 
                                                                                {
                                                                                    var mailOptions = {
                                                                                        from: emailHeading, // sender address
                                                                                        to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                        replyTo: replyTo,
                                                                                        subject: "tms CARD CASH IN FAILURE", // Subject line
                                                                                        text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                    };
                                                                                        
                                                                                    transporter.sendMail(mailOptions, function(error, info){
                                                                                        if (error) {
                                                                                            logger.info(error);
                                                                                        } else {
                                                                                            logger.info('Email sent: ' + info.response);
                                                                                        }
                                                                                    });
                                                                                    logger.info("Database connection error 1.: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                    res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                }
                                                                                else
                                                                                {
                                                                                    var refundAmount = (parseFloat(love.rows[0].amount) + parseFloat(Tfees)).toFixed(2);
                                                                                    var qry2 =
                                                                                        "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                                                                                    pool.query(qry2, [refundAmount, tid], (err, resul) => {
                                                                                        if (err) 
                                                                                        {
                                                                                            var mailOptions = {
                                                                                                from: emailHeading, // sender address
                                                                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                replyTo: replyTo,
                                                                                                subject: "tms CARD CASH IN FAILURE", // Subject line
                                                                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                            };
                                                                                                
                                                                                            transporter.sendMail(mailOptions, function(error, info){
                                                                                                if (error) {
                                                                                                    logger.info(error);
                                                                                                } else {
                                                                                                    logger.info('Email sent: ' + info.response);
                                                                                                }
                                                                                            });
                                                                                            logger.info("Database connection error 2.: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                            return res.status(500).send({"status": 500, "message": "An Error Occurred..."});
                                                                                        }else
                                                                                        {
                                                                                            var preBal = 0.00;
                                                                                            var newBal = 0.00;
                                                                                            preBal = love.rows[0].amount;
                                                                                            newBal = parseFloat(refundAmount);
                                                                                            var waA = "INSERT INTO walletactivies " + 
                                                                                                "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                                                                                                "VALUES ($1, $2, $3, $4, $5, $6)";
                                                                                            pool.query(waA, [tid, Tfees, preBal, newBal, 
                                                                                                "CREDIT", "CARD REVERSAL FOR WALLET TRANSFER TO " + destination + ". NAME: " + receivername], (err, resul) => {
                                                                                                if (err) 
                                                                                                {
                                                                                                    var mailOptions = {
                                                                                                        from: emailHeading, // sender address
                                                                                                        to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                        replyTo: replyTo,
                                                                                                        subject: "tms CARD CASH IN FAILURE", // Subject line
                                                                                                        text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                    };
                                                                                                        
                                                                                                    transporter.sendMail(mailOptions, function(error, info){
                                                                                                        if (error) {
                                                                                                            logger.info(error);
                                                                                                        } else {
                                                                                                            logger.info('Email sent: ' + info.response);
                                                                                                        }
                                                                                                    });
                                                                                                    logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                    return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                                }else
                                                                                                {
                                                                                                    var qry3 = "INSERT INTO etranzactstatus " + 
                                                                                                        "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                                                                                                        "bankname, bankcode, accountnumber, status, transactiontype, tmsfee, superagentfee, ref)" + 
                                                                                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                                                    pool.query(qry3, [JSON.stringify(result), JSON.stringify(result), JSON.stringify(result), 
                                                                                                        JSON.stringify(result), tid, amount, toCus, "NA", 
                                                                                                        bankcode, destination, "ERROR OCCURRED", "CASH IN", tmsfee, superagentfee, transRef4], (err, resul) => {
                                                                                                        if (err) 
                                                                                                        {
                                                                                                            var mailOptions = {
                                                                                                                from: emailHeading, // sender address
                                                                                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                                replyTo: replyTo,
                                                                                                                subject: "tms CARD CASH IN FAILURE", // Subject line
                                                                                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                            };
                                                                                                                
                                                                                                            transporter.sendMail(mailOptions, function(error, info){
                                                                                                                if (error) {
                                                                                                                    logger.info(error);
                                                                                                                } else {
                                                                                                                    logger.info('Email sent: ' + info.response);
                                                                                                                }
                                                                                                            });
                                                                                                            logger.info("Error: " + err + ". Time: " +  new Date().toLocaleString());
                                                                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                            return res.header("Content-Type",'Application/json').status(500).send(JSON.stringify(result));
                                                                                                        }else
                                                                                                        {
                                                                                                            var mailOptions = {
                                                                                                                from: emailHeading, // sender address
                                                                                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                                replyTo: replyTo,
                                                                                                                subject: "tms CARD CASH IN FAILURE", // Subject line
                                                                                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                            };
                                                                                                                
                                                                                                            transporter.sendMail(mailOptions, function(error, info){
                                                                                                                if (error) {
                                                                                                                    logger.info(error);
                                                                                                                } else {
                                                                                                                    logger.info('Email sent: ' + info.response);
                                                                                                                }
                                                                                                            });
                                                                                                            return res.header("Content-Type",'Application/json').status(500).send(JSON.stringify(result));
                                                                                                        }
                                                                                                    });
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
                                                }
                                            });
                                        }
                                    });
                                }
                            }
                        }
                    }
                });
            }
        }
    });
});

//DELETE
//KEYSTONE
router.get("/cashin", function(req, res) 
{
    var tid = req.headers.tid;
    var bankcode = req.headers.bankcode;//Headquarters code
    var destination = req.headers.destination;//Customer Account
    var amount = req.headers.amount.replace(/,/g, '');
    var mainamount = req.headers.mainamount.replace(/,/g, '');
    var fee = req.headers.fee.replace(/,/g, '');
    var tmsfee = req.headers.tmsfee;
    var superagentfee = req.headers.superagentfee;
    var description = req.headers.description;
    var termRef = req.headers.rrn;
    var receivername = req.headers.receivername;
    var bankname = req.headers.bankname;
    var supersuperfee = req.headers.supersuperfee;

    logger.info("CASH IN WALLET");
    logger.info(req.headers);

    if(bankcode.length > 3)
    {
        var bk = bankcode.slice(0, 3);
        bankcode = bk;
    }

    var rrn = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef1 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef2 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef3 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef4 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef5 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef6 = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var transRef7 = randomstring.generate({
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
                            var supersuper = 0.00;
                            var vatKar = 0.00;
                            var etzn = 0.00;
                            var vatEtzn = 0.00;
                            var agentamount = 0.00;
                            var toCus = 0.00;
                            var Tfees = 0.00;
            
                            tmsfee = parseFloat(terminal.rows[0].cttms);
                            superagentfee = parseFloat(terminal.rows[0].ctsuperagent);
                            supersuperfee = parseFloat(terminal.rows[0].ctsupersuperagent);
                            supersuper = superagentfee;
                            var usemsc = 0.00;
                            var stamp = 0.00;
                            Tfees = (parseFloat(tmsfee) + 
                                    parseFloat(superagentfee) + parseFloat(supersuperfee)).toFixed(2);
                            toCus = amount;
                            
                            var totAgentAmount = (parseFloat(love.rows[0].amount) - parseFloat(Tfees)).toFixed(2);
                            if(totAgentAmount < 0)
                            {
                                return res.status(500).send({"status": 500, "message": "Amount too high"});
                            }else
                            {
                                if(isNumber(amount) === false)
                                {
                                    console.log(req.headers);
                                    return res.status(500).send({"status": 500, "message": "Invalid Amount. Retry Later"});
                                }else
                                {
                                    var qry2 =
                                        "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                                    pool.query(qry2, [totAgentAmount, tid], (err, resul) => {
                                        if (err) 
                                        {
                                            return res.status(500).send({"status": 500, "message": "An Error Occurred..."});
                                        }else
                                        {
                                            console.log(supersuper);
                                            console.log(tmsfee);
                                            console.log(superagentfee);
                                            console.log(toCus);
                                            //return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "FEES DOES NOT TALLY"});
                                            var preBal = 0.00;
                                            var newBal = 0.00;
                                            preBal = love.rows[0].amount;
                                            newBal = parseFloat(totAgentAmount);
                                            var waA = "INSERT INTO walletactivies " + 
                                                "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                                                "VALUES ($1, $2, $3, $4, $5, $6)";
                                            pool.query(waA, [tid, amount, preBal, newBal, 
                                                "DEBIT", "CARD TRANSFER TO " + destination + ". NAME: " + receivername], (err, resul) => {
                                                if (err) 
                                                {
                                                    logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                    return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                }else
                                                {
                                                    var enc = new Object();
                                                    enc.bankCode = bankcode;
                                                    enc.accountNumber = destination;
                                                    console.log("Pre Validation: " + JSON.stringify(enc));

                                                    var plainText = JSON.stringify(enc);
                                                    var cipherText = wisencrypt(plainText, keyBase64, ivBase64);
                                                    
                                                    var sendout = new Object();
                                                    sendout.encRequest = cipherText;
                                                    console.log("Post Validation: " + JSON.stringify(sendout));

                                                    var clientServerOptions = {
                                                        uri: "http://41.203.111.118:9091/thirdParty/FT/Service/api/interbank/nameEnquiry",
                                                        body: JSON.stringify(sendout),
                                                        method: 'POST',
                                                        headers: {
                                                            'Content-Type': 'application/json'
                                                        }
                                                    }
                                                    request(clientServerOptions, function (error, response) {
                                                        if(error)
                                                        {
                                                            logger.info("ERROR: " + error);
                                                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful"});
                                                        }
                                                        if(response)
                                                        {
                                                            logger.info(response.statusCode);
                                                            logger.info("RESPONSE");
                                                            logger.info(response.body);
                                                            if(response.statusCode == 200)
                                                            {
                                                                var rResponse = JSON.parse(response.body);
                                                                var decipherText = JSON.parse(wisdecrypt(rResponse.encResponse, keyBase64, ivBase64));
                                                                logger.info(decipherText);
                                                                if(decipherText.responseCode === "00")
                                                                {
                                                                    receivername = decipherText.accountName;
                                                                    if(1)
                                                                    {
                                                                        var enc = new Object();
                                                                        enc.txnId = transRef4;
                                                                        enc.beneficiaryAccountNumber = destination;
                                                                        enc.beneficiaryAccountName = receivername;
                                                                        enc.destBankCode = bankcode;
                                                                        enc.amount = toCus;
                                                                        enc.fee = "10.00";
                                                                        enc.senderAccountNumber = "1007358176";
                                                                        enc.senderAccountName = "CREDIT ASSIST INVESTMENT LIMITED";
                                                                        enc.narration = description;
                                                                        console.log("Pre Validation: " + JSON.stringify(enc));
                                                                        var plainText = JSON.stringify(enc);
                                                                        var cipherText = wisencrypt(plainText, keyBase64, ivBase64);
                                                                        var sendout = new Object();
                                                                        sendout.encRequest = cipherText;
                                                                        console.log("Post Validation: " + JSON.stringify(sendout));
                                                                        var xml = JSON.stringify(sendout);

                                                                        var clientServerOptions = {
                                                                            uri: "http://41.203.111.118:9091/thirdParty/FT/Service/api/interbank/FT",
                                                                            body: JSON.stringify(sendout),
                                                                            method: 'POST',
                                                                            headers: {
                                                                                'Content-Type': 'application/json'
                                                                            }
                                                                        }
                                                                        request(clientServerOptions, function (error, response) {
                                                                            if(error)
                                                                            {
                                                                                logger.info("ERROR: " + error);
                                                                                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful"});
                                                                            }
                                                                            if(response)
                                                                            {
                                                                                logger.info(response.statusCode);
                                                                                logger.info("RESPONSE");
                                                                                logger.info(response.body);
                                                                                if(response.statusCode == 200 && response.body)
                                                                                {
                                                                                    var d = response.body.slice(0, 1);
                                                                                    if(d == '{' || d == '[')
                                                                                    {
                                                                                        var rResponse = JSON.parse(response.body);
                                                                                        var decipherText = JSON.parse(wisdecrypt(rResponse.encResponse, keyBase64, ivBase64));
                                                                                        logger.info(decipherText);
                                                                                        if(decipherText.responseCode === "00")
                                                                                        {
                                                                                            var result = JSON.stringify(decipherText);
                                                                                            var rt = `{"SingleTransfersResult": {"Response": {"Code": "1000","Message": "Transaction Successful"}}}`;
                                                                                            var qry2 = "INSERT INTO frometranzact " + 
                                                                                                "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                                                                                "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                                                                                "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, stampduty, vatkar, varetzn, etranzactresponse, etranzactecho, mainamount, fee, ref, dump)" + 
                                                                                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39)";
                                                                                            pool.query(qry2, ["tms HOLDING", "tms HOLDING", "NA", transRef, tid, "NA", "CASH DEPOSIT / TRANSFER", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                                                                                terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                                                                terminal.rows[0].accountname, rrn, "Transaction Success - CARD", amount, agentamount, superagentfee, tmsfee, usemsc, terminal.rows[0].switchfee, destination, toCus, stamp, vatKar, supersuper, "FILE SUCCESSFULLY UPLOADED", JSON.stringify(result), mainamount, fee, termRef, xml], (err, resul) => {
                                                                                                if (err) 
                                                                                                {
                                                                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                                }else
                                                                                                {
                                                                                                    var qry9 = "INSERT INTO requery " + 
                                                                                                        "(message, response, accountname, accountcode, accountnumber, accountbank, ref, amount, status, tid) " + 
                                                                                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";
                                                                                                    pool.query(qry9, [xml, JSON.stringify(result), receivername, bankcode, 
                                                                                                        destination, bankname, transRef4, toCus, "NOT VALIDATED", tid], (err, resul) => {
                                                                                                        if (err) 
                                                                                                        {
                                                                                                            logger.info(err);
                                                                                                            logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 5x");
                                                                                                            logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                            return res.header("Content-Type",'Application/json').status(200).send(rt);
                                                                                                        }else
                                                                                                        {
                                                                                                            var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                                "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                                "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                                ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                                            pool.query(qry3, [tid, "", superagentfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                                terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                                terminal.rows[0].saaccountname, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountnumber,
                                                                                                                terminal.rows[0].saaccountbank, "NOT SETTLED", "superagent"+tid, termRef], (err, resul) => {
                                                                                                                if (err) 
                                                                                                                {
                                                                                                                    logger.info(err);
                                                                                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                                                }else
                                                                                                                {
                                                                                                                    var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                                        "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                                        "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                                        ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                                                    pool.query(qry3, [tid, "", tmsfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                                        terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                                        terminal.rows[0].caaccountname, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountnumber,
                                                                                                                        terminal.rows[0].caaccountbank, "NOT SETTLED", "tms" + tid, termRef], (err, resul) => {
                                                                                                                        if (err) 
                                                                                                                        {
                                                                                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                            res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                                                        }else
                                                                                                                        {
                                                                                                                            var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                                                "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                                                "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                                                ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                                                            pool.query(qry3, [tid, "", supersuper, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                                                terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                                                terminal.rows[0].superaccountname, terminal.rows[0].superaccountcode, terminal.rows[0].superaccountnumber,
                                                                                                                                terminal.rows[0].superbankname, "NOT SETTLED", "supersuper" + tid, termRef], (err, resul) => {
                                                                                                                                if (err) 
                                                                                                                                {
                                                                                                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                                                                }else
                                                                                                                                {
                                                                                                                                    var qry3 = "INSERT INTO agencyinstant " + 
                                                                                                                                        "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                                                                        "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                                                                        ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                                                                    pool.query(qry3, [tid, "", toCus, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                                                                        terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                                                                                                        receivername, bankcode, destination,
                                                                                                                                        bankname, "SETTLED", "cus" + tid, termRef], (err, resul) => {
                                                                                                                                        if (err) 
                                                                                                                                        {
                                                                                                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                                            res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                                                                        }else
                                                                                                                                        {
                                                                                                                                            //Customer Settlement
                                                                                                                                            var qry10 = "INSERT INTO agentsettlement " + 
                                                                                                                                                "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                                                                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                                                                            pool.query(qry10, [tid, toCus, bankname, 
                                                                                                                                                bankcode, receivername, 
                                                                                                                                                destination, description + " - " + JSON.stringify(result), termRef], (err, resul) => {
                                                                                                                                                if (err) 
                                                                                                                                                {
                                                                                                                                                    logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                                                                                    logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                                                    return res.header("Content-Type",'Application/json').status(200).send(rt);
                                                                                                                                                }else
                                                                                                                                                {
                                                                                                                                                    logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                                                    return res.header("Content-Type",'Application/json').status(200).send(rt);
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
                                                                                        }else
                                                                                        {
                                                                                            var result = JSON.stringify(decipherText);
                                                                                            var rt = `{"SingleTransfersResult": {"Response": {"Code": "1000","Message": "` +
                                                                                            decipherText.responseMessage + `"}}}`;
                                                                                            var qry = "SELECT * FROM walletbalance WHERE tid = $1";
                                                                                            pool.query(qry, [tid], (err, love) => { 
                                                                                                if (err) 
                                                                                                {
                                                                                                    var mailOptions = {
                                                                                                        from: emailHeading, // sender address
                                                                                                        to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                        replyTo: replyTo,
                                                                                                        subject: "tms CARD CASH IN FAILURE", // Subject line
                                                                                                        text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                    };
                                                                                                        
                                                                                                    transporter.sendMail(mailOptions, function(error, info){
                                                                                                        if (error) {
                                                                                                            logger.info(error);
                                                                                                        } else {
                                                                                                            logger.info('Email sent: ' + info.response);
                                                                                                        }
                                                                                                    });
                                                                                                    logger.info("Database connection error 1.: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                    res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                                }
                                                                                                else
                                                                                                {
                                                                                                    var refundAmount = (parseFloat(love.rows[0].amount) + parseFloat(Tfees)).toFixed(2);
                                                                                                    var qry2 =
                                                                                                        "UPDATE walletbalance SET amount = $1 WHERE tid = $2";
                                                                                                    pool.query(qry2, [refundAmount, tid], (err, resul) => {
                                                                                                        if (err) 
                                                                                                        {
                                                                                                            var mailOptions = {
                                                                                                                from: emailHeading, // sender address
                                                                                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                                replyTo: replyTo,
                                                                                                                subject: "tms CARD CASH IN FAILURE", // Subject line
                                                                                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                            };
                                                                                                                
                                                                                                            transporter.sendMail(mailOptions, function(error, info){
                                                                                                                if (error) {
                                                                                                                    logger.info(error);
                                                                                                                } else {
                                                                                                                    logger.info('Email sent: ' + info.response);
                                                                                                                }
                                                                                                            });
                                                                                                            logger.info("Database connection error 2.: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                            return res.status(500).send({"status": 500, "message": "An Error Occurred..."});
                                                                                                        }else
                                                                                                        {
                                                                                                            var preBal = 0.00;
                                                                                                            var newBal = 0.00;
                                                                                                            preBal = love.rows[0].amount;
                                                                                                            newBal = parseFloat(refundAmount);
                                                                                                            var waA = "INSERT INTO walletactivies " + 
                                                                                                                "(tid, amount, oldamount, newamount, transmode, transinfo)" + 
                                                                                                                "VALUES ($1, $2, $3, $4, $5, $6)";
                                                                                                            pool.query(waA, [tid, Tfees, preBal, newBal, 
                                                                                                                "CREDIT", "CARD REVERSAL FOR WALLET TRANSFER TO " + destination + ". NAME: " + receivername], (err, resul) => {
                                                                                                                if (err) 
                                                                                                                {
                                                                                                                    var mailOptions = {
                                                                                                                        from: emailHeading, // sender address
                                                                                                                        to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                                        replyTo: replyTo,
                                                                                                                        subject: "tms CARD CASH IN FAILURE", // Subject line
                                                                                                                        text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                                    };
                                                                                                                        
                                                                                                                    transporter.sendMail(mailOptions, function(error, info){
                                                                                                                        if (error) {
                                                                                                                            logger.info(error);
                                                                                                                        } else {
                                                                                                                            logger.info('Email sent: ' + info.response);
                                                                                                                        }
                                                                                                                    });
                                                                                                                    logger.info("Database Issue. User: " + err + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                    return res.status(500).send({"status": 500, "message": "Transaction Failed."});
                                                                                                                }else
                                                                                                                {
                                                                                                                    var qry3 = "INSERT INTO etranzactstatus " + 
                                                                                                                        "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                                                                                                                        "bankname, bankcode, accountnumber, status, transactiontype, tmsfee, superagentfee, ref)" + 
                                                                                                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                                                                    pool.query(qry3, [JSON.stringify(result), JSON.stringify(result), JSON.stringify(result), 
                                                                                                                        JSON.stringify(result), tid, amount, toCus, "NA", 
                                                                                                                        bankcode, destination, "ERROR OCCURRED", "CASH IN", tmsfee, superagentfee, transRef4], (err, resul) => {
                                                                                                                        if (err) 
                                                                                                                        {
                                                                                                                            var mailOptions = {
                                                                                                                                from: emailHeading, // sender address
                                                                                                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                                                replyTo: replyTo,
                                                                                                                                subject: "tms CARD CASH IN FAILURE", // Subject line
                                                                                                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                                            };
                                                                                                                                
                                                                                                                            transporter.sendMail(mailOptions, function(error, info){
                                                                                                                                if (error) {
                                                                                                                                    logger.info(error);
                                                                                                                                } else {
                                                                                                                                    logger.info('Email sent: ' + info.response);
                                                                                                                                }
                                                                                                                            });
                                                                                                                            logger.info("Error: " + err + ". Time: " +  new Date().toLocaleString());
                                                                                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                            return res.header("Content-Type",'Application/json').status(500).send(rt);
                                                                                                                        }else
                                                                                                                        {
                                                                                                                            var mailOptions = {
                                                                                                                                from: emailHeading, // sender address
                                                                                                                                to: "c.olalude@tmsng.com, f.ogunleye@tmsng.com, m.okoh@tmsng.com, b.adebayo@tmsng.com, o.otuyemi@tmsng.com", // list of receivers
                                                                                                                                replyTo: replyTo,
                                                                                                                                subject: "tms CARD CASH IN FAILURE", // Subject line
                                                                                                                                text: "PROCESSOR FAILED WITH \n" + JSON.stringify(result) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                                                                            };
                                                                                                                                
                                                                                                                            transporter.sendMail(mailOptions, function(error, info){
                                                                                                                                if (error) {
                                                                                                                                    logger.info(error);
                                                                                                                                } else {
                                                                                                                                    logger.info('Email sent: ' + info.response);
                                                                                                                                }
                                                                                                                            });
                                                                                                                            return res.header("Content-Type",'Application/json').status(500).send(rt);
                                                                                                                        }
                                                                                                                    });
                                                                                                                }
                                                                                                            });
                                                                                                        }
                                                                                                    });
                                                                                                }
                                                                                            });
                                                                                        }
                                                                                    }else
                                                                                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful 2x"});
                                                                                }else
                                                                                    return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful"});
                                                                            }
                                                                        });
                                                                    }
                                                                }else
                                                                {
                                                                    return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful"});
                                                                }
                                                            }else
                                                                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful"});
                                                        }
                                                    });
                                                }
                                            });
                                        }
                                    });
                                }
                            }
                        }
                    }
                });
            }
        }
    });
});

//DELETE
//PENDING CASH IN
//CARD CASH IN
router.post("/penddeposit", function(req, res) 
{
    console.log(req.body);
    logger.info("PENDING CASH IN WALLET. NOT TO BE HONOURED");
    logger.info(req.body);
    return res.status(200).send({"status": 200, "message": "An Error Occurred. Not Successful."});
});

module.exports.router = router;