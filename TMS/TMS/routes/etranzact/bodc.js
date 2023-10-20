var router = express.Router();


var request = require('request').defaults({ rejectUnauthorized: false })

function formatAmoutWell(input)
{
  var amount = input.replace(/,/g, '');
  return amount;
}


function parseEachRule(rule, amount)
{
    var i = 0, k = 0;
    var firstLoop = "";
    var secondLoop = "";
    var thirdLoop = "";
    var loop = 0;
    for(i = 0; i < rule.length; i++) 
    {
        if(rule.charAt(i) === '-')
        {
            loop = 1;
            k = 0;
            continue;
        }
        
        if(rule.charAt(i) === '=')
        {
            loop = 2;
            k = 0;
            continue;
        }
        
        if(loop == 0)
        {
            firstLoop = firstLoop + rule.charAt(i); //Take note
            k = k + 1;
        }else if(loop == 1)
        {
            secondLoop = secondLoop + rule.charAt(i); //Take note
            k = k + 1;
        }else if(loop == 2)
        {
            thirdLoop = thirdLoop + rule.charAt(i); //Take note
            k = k + 1;
        }
    }

    if(parseFloat(amount) <= parseFloat(secondLoop))
    {
        return thirdLoop;
    }
    return "NULL";
}


function parseRule(str, amount)
{
    var rule = [];
    var temp = "";
    var outamt = "";
    var i = 0, j = 0, k = 0;
    
    outamt = formatAmoutWell(amount);

    for(i = 0; i < str.length; i++) 
    {
        if ((str.charAt(i) === '#') && (str.charAt(i + 1) === '#') 
          && (str.charAt(i + 2) === '#')) 
        {
            rule.push(temp);
            i = i + 2;
            j = j + 1;
            k = 0;
            temp = "";
        }else
        {
            temp = temp + str.charAt(i);
            k = k + 1;
        }
    }
    
    for(i = 0; i < j; i++)
    {
        fee = parseEachRule(rule[i], outamt);
        if(fee !== "NULL")
        {
            return fee;
        }
    }

    if(fee.length < 2)
    {
    	console.log("Fee band not exist. Terminate");
        return "NULL";
    }
    return fee;
}


function sendTransfer(terminal, json)
{
    var tmsfee = "";
    var superagentfee = "";
    if(terminal.rows[0].percentagerule === "true")
    {
        var kamt = parseRule(terminal.rows[0].tmstransferrule, json.creditamount);
        if(kamt === "NULL")
        {
            tmsfee = "100.00";
        }else
        {
            var karr = ((parseFloat(kamt) / 100) * parseFloat(json.creditamount)).toFixed(2);
            tmsfee = karr.toString();
        }

        var kamt = parseRule(terminal.rows[0].superagenttransferrule, json.creditamount);
        if(kamt === "NULL")
        {
            superagentfee = "20.00";
        }else
        {
            var karr = ((parseFloat(kamt) / 100) * parseFloat(json.creditamount)).toFixed(2);
            superagentfee = karr.toString();
        }
    }else
    {
        var kamt = parseRule(terminal.rows[0].tmstransferrule, json.creditamount);
        if(kamt === "NULL")
        {
            tmsfee = "100.00";
        }else
        {
            tmsfee = kamt.toString();
        }

        var kamt = parseRule(terminal.rows[0].superagenttransferrule, json.creditamount);
        if(kamt === "NULL")
        {
            superagentfee = "20.00";
        }else
        {
            superagentfee = kamt.toString();
        }
    }
    var clientServerOptions = {
        uri: "http://localhost:8001/tms/etranzact/cashtransfer",
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'tid': json.tid,
            'bankcode': json.customerbankcode,
            'destination': json.customeraccountnumber,
            'amount': json.amount,
            'mainamount': json.creditamount,
            'fee': json.fee,
            'rrn': json.rrn,
            'tmsfee': tmsfee,
            'superagentfee': superagentfee,
            'description': json.description
        }
    }
    request(clientServerOptions, function (error, response) {
        if(error)
        {
            logger.info("BODC ACCOUNT TRANSFER ERROR GOTTEN. " + error);
            return;
        }
        if(response)
        {
            var qry2 = "INSERT INTO frombodc " + 
                "(toetranzact, frometranzact, tid) " + 
                "VALUES ($1, $2, $3)";
            pool.query(qry2, [clientServerOptions, response.body, json.tid], (err, resul) => {
                if (err) 
                {
                    logger.info("ACCOUNT TRANSFER Issue" + err + ". Time: " +  new Date().toLocaleString());
                    return;
                }else
                {
                    logger.info("BODC ACCOUNT TRANSFER RESPONSE: " + response.body);
                    return;
                }
            });
        }
    });  
}


function sendDeposit(terminal, json)
{
    var tmsfee = "";
    var superagentfee = "";
    if(terminal.rows[0].percentagerule === "true")
    {
        var kamt = parseRule(terminal.rows[0].tmstransferrule, json.creditamount);
        if(kamt === "NULL")
        {
            tmsfee = "100.00";
        }else
        {
            var karr = ((parseFloat(kamt) / 100) * parseFloat(json.creditamount)).toFixed(2);
            tmsfee = karr.toString();
        }

        var kamt = parseRule(terminal.rows[0].superagenttransferrule, json.creditamount);
        if(kamt === "NULL")
        {
            superagentfee = "20.00";
        }else
        {
            var karr = ((parseFloat(kamt) / 100) * parseFloat(json.creditamount)).toFixed(2);
            superagentfee = karr.toString();
        }
    }else
    {
        var kamt = parseRule(terminal.rows[0].tmstransferrule, json.creditamount);
        if(kamt === "NULL")
        {
            tmsfee = "100.00";
        }else
        {
            tmsfee = kamt.toString();
        }

        var kamt = parseRule(terminal.rows[0].superagenttransferrule, json.creditamount);
        if(kamt === "NULL")
        {
            superagentfee = "20.00";
        }else
        {
            superagentfee = kamt.toString();
        }
    }
    var clientServerOptions = {
        uri: "http://localhost:8001/tms/etranzact/depositcash",
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'tid': json.tid,
            'bankcode': json.customerbankcode,
            'destination': json.customeraccountnumber,
            'amount': json.amount,
            'mainamount': json.creditamount,
            'fee': json.fee,
            'rrn': json.rrn,
            'tmsfee': tmsfee,
            'superagentfee': superagentfee,
            'description': json.description
        }
    }
    request(clientServerOptions, function (error, response) {
        if(error)
        {
            logger.info("BODC CASH DEPOSIT ERROR GOTTEN. " + error);
            return;
        }
        if(response)
        {
            var qry2 = "INSERT INTO frombodc " + 
                "(toetranzact, frometranzact, tid) " + 
                "VALUES ($1, $2, $3)";
            pool.query(qry2, [clientServerOptions, response.body, json.tid], (err, resul) => {
                if (err) 
                {
                    logger.info("Cash Deposit Issue" + err + ". Time: " +  new Date().toLocaleString());
                    return;
                }else
                {
                    logger.info("BODC CASH DEPOSIT RESPONSE: " + response.body);
                    return;
                }
            });
        }
    });  
}


function sendWithdrawal(terminal, json)
{
    var tmsfee = "";
    var superagentfee = "";
    if(terminal.rows[0].percentagerule === "true")
    {
        var kamt = parseRule(terminal.rows[0].tmsfeerule, json.creditamount);
        if(kamt === "NULL")
        {
            tmsfee = "100.00";
        }else
        {
            var karr = ((parseFloat(kamt) / 100) * parseFloat(json.creditamount)).toFixed(2);
            tmsfee = karr.toString();
        }

        var kamt = parseRule(terminal.rows[0].superagentfeerule, json.creditamount);
        if(kamt === "NULL")
        {
            superagentfee = "20.00";
        }else
        {
            var karr = ((parseFloat(kamt) / 100) * parseFloat(json.creditamount)).toFixed(2);
            superagentfee = karr.toString();
        }
    }else
    {
        var kamt = parseRule(terminal.rows[0].tmsfeerule, json.creditamount);
        if(kamt === "NULL")
        {
            tmsfee = "100.00";
        }else
        {
            tmsfee = kamt.toString();
        }

        var kamt = parseRule(terminal.rows[0].superagentfeerule, json.creditamount);
        if(kamt === "NULL")
        {
            superagentfee = "20.00";
        }else
        {
            superagentfee = kamt.toString();
        }
    }
    var clientServerOptions = {
        uri: "http://localhost:8001/tms/etranzact/cardtoaccount",
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'tid': json.tid,
            'amount': json.amount,
            'mainamount': json.creditamount,
            'fee': json.fee,
            'rrn': json.rrn,
            'tmsfee': tmsfee,
            'superagentfee': superagentfee
        }
    }
    //console.log(clientServerOptions);
    request(clientServerOptions, function (error, response) {
        if(error)
        {
            logger.info("BODC CASH WITHDRAWAL ERROR GOTTEN. " + error);
            return;
        }
        if(response)
        {
            var qry2 = "INSERT INTO frombodc " + 
                "(toetranzact, frometranzact, tid) " + 
                "VALUES ($1, $2, $3)";
            pool.query(qry2, [clientServerOptions, response.body, json.tid], (err, resul) => {
                if (err) 
                {
                    logger.info("Cash Withdrawal Issue: " + err + ". Time: " +  new Date().toLocaleString());
                    return;
                }else
                {
                    logger.info("BODC CASH WITHDRAWAL RESPONSE: " + response.body);
                    return;
                }
            });
        }
    });  
}


router.post("/notify", function(req, res)
{
	logger.info("Inside BODC Request");
	req.setTimeout(30000); //set a 30s timeout for this request
	try
    {
		logger.info("BODC notification gotten from:  " + req.clientIp);
		var json = JSON.parse(JSON.stringify(req.body));
        
        var username = req.headers.username;
        var password = req.headers.password;
        var tid = req.headers.tid;

        if(username !== "bodcpos" || password !== "micahlv_123")
        {
            var obj = new Object();
			obj.success = false;
			obj.result = null;
			var error = new Object();
			error.message = "Wrong Authentication Details.";
			error.code = -1;
			arr = [];
			arr.push(error);
			obj.errors = arr;
			logger.info("Dodc notification error from:  " + req.clientIp + " not processed");
			res.header("Content-Type",'application/json').status(400).send(obj);
        }else
        {
            var qry = "SELECT * FROM terminalconfiguration WHERE tid = $1";
            pool.query(qry, [tid], (err, terminal) => {
                if (err) 
                {
                    return res.status(500).send({"status": 500, "message": "Invalid Tid. Contact tms"});
                }else
                {
                    if(terminal.rows.length !== 1)
                    {
                        return res.status(500).send({"status": 500, "message": "Tid not registered. Contact tms"});
                    }else if(terminal.rows[0].blocked === "true")
                    {
                        return res.status(500).send({"status": 500, "message": "Tid blocked. Contact tms"});
                    }else if(parseFloat(json.amount) > parseFloat(terminal.rows[0].maxamount))
                    {
                        return res.status(500).send({"status": 500, "message": "Amount Limit Exceded. Contact tms"});
                    }else if(json.resp !== "00")
                    {
                        return res.status(500).send({"status": 500, "message": "Transaction was not Approved..."});
                    }else
                    {
                        var ejarr = json;
                        arrValue = [];
                        val = 1;
                        strg = "";
                        main = "(stan, extras, paymentmethod, aid, card_expiry, card_holder, card_type, mid, " + 
                        "masked_pan, rrn, auth_code, amount, date_trans, " + 
                        "mti, processing_code, response_code, terminal_id, " + 
                        "tmo, bodcdump, sanef" +
                        ") VALUES ";

                        strg += "(";
                        arrValue.push(ejarr.stan);
                        strg += "$" + val.toString() + ",";
                        val++;
                        arrValue.push(ejarr.extras + " " + ejarr.customerbankcode + " " + ejarr.customeraccountnumber);
                        strg += "$" + val.toString() + ",";
                        val++;
                        arrValue.push(ejarr.paymentmethod);
                        strg += "$" + val.toString() + ",";
                        val++;
                        arrValue.push(ejarr.aid);
                        strg += "$" + val.toString() + ",";
                        val++;
                        arrValue.push(ejarr.expdate);
                        strg += "$" + val.toString() + ",";
                        val++;
                        arrValue.push(ejarr.cardname);
                        strg += "$" + val.toString() + ",";
                        val++;
                        arrValue.push(ejarr.cardtype);
                        strg += "$" + val.toString() + ",";
                        val++;
                        arrValue.push(ejarr.mid);
                        strg += "$" + val.toString() + ",";
                        val++;
                        arrValue.push(ejarr.mpan);
                        strg += "$" + val.toString() + ",";
                        val++;
                        arrValue.push(ejarr.rrn);
                        strg += "$" + val.toString() + ",";
                        val++;
                        arrValue.push(ejarr.acode);
                        strg += "$" + val.toString() + ",";
                        val++;
                        arrValue.push(ejarr.amount);
                        strg += "$" + val.toString() + ",";
                        val++;
                        arrValue.push(ejarr.timestamp);
                        strg += "$" + val.toString() + ",";
                        val++;
                        arrValue.push(ejarr.mti);
                        strg += "$" + val.toString() + ",";
                        val++;
                        arrValue.push(ejarr.ps);
                        strg += "$" + val.toString() + ",";
                        val++;
                        arrValue.push(ejarr.resp);
                        strg += "$" + val.toString() + ",";
                        val++; 
                        arrValue.push(ejarr.tid);
                        strg += "$" + val.toString() + ",";
                        val++;
                        arrValue.push(ejarr.tmo);
                        strg += "$" + val.toString() + ",";
                        val++;
                        arrValue.push(ejarr);
                        strg += "$" + val.toString() + ",";
                        val++;
                        arrValue.push(ejarr.sanef);
                        strg += "$" + val.toString() + "";
                        val++;
                        strg += ")";

                        pool.query("INSERT INTO ejournal " + main + strg, arrValue, (err, result) => {
                            if (err) 
                            {
                                var obj = new Object();
                                obj.success = false;
                                obj.result = null;
                                var error = new Object();
                                error.message = "Processing Notification Error.";
                                error.code = -1;
                                arr = [];
                                arr.push(error);
                                obj.errors = arr;
                                logger.info("Dodc notification processing error from:  " + req.clientIp + " not processed");
                                res.header("Content-Type",'application/json').status(400).send(obj);
                            }
                            else
                            {
                                if(ejarr.transtype === "CASH WITHDRAWAL")
                                {
                                    sendWithdrawal(terminal, json);
                                }else if(ejarr.transtype === "CASH DEPOSIT")
                                {
                                    //sendDeposit(terminal, json);
                                }else if(ejarr.transtype === "ACCOUNT TRANSFER")
                                {
                                    //sendTransfer(terminal, json);
                                }
                                var obj = new Object();
                                obj.success = true;
                                obj.result = true;
                                var error = new Object();
                                error.message = "Successful";
                                error.code = 0;
                                error.remarks = "Your transaction " + ejarr.transtype + " is currently being processed";
                                arr = [];
                                arr.push(error);
                                obj.errors = arr;
                                res.header("Content-Type",'application/json').status(200).send(obj);
                            }
                        });
                    }
                }
            });
        }
    }catch(e)
    {
        logger.info(e);
        logger.error("Push message gotten from: " + req.clientIp + ". Error Occurred ");
        res.status(500).send({});
    }
});

module.exports.router = router;