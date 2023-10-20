var router = express.Router();
var request = require('request').defaults({ rejectUnauthorized: false })
const { join } = require('path');

const wsdlURL = "https://www.etranzact.net/FGate/ws?wsdl";//Live Ip
var pin = "Ll2gQZMusI747Vo9K9T65w==";
var karraboholdingtid = "2140010002";
var vat = "7.5";

var vatAct = "0122814626";
var vatActCode = "035";
var vatBank = "WEMA BANK";

//CASH WITHDRAWAL
//debit customer card, credit karrabo holding account
router.get("/cardtoaccount", function(req, res) 
{
    var tid = req.headers.tid;
    var amount = parseFloat(req.headers.amount.replace(/,/g, ''));
    var karrabofee = req.headers.karrabofee;
    var superagentfee = req.headers.superagentfee;
    var mainamount = req.headers.mainamount.replace(/,/g, '');
    var rrn = req.headers.rrn;

    var transRef = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    logger.info("CASH WITHDRAWAL");
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
                var usemsc = ((parseFloat(terminal.rows[0].msc) / 100) * parseFloat(amount)).toFixed(2);
                if(usemsc > 1000)
                    usemsc = 1000.00;
                
                var stamp = 0.00;
                if(parseFloat(amount) >= 10000)
                    stamp = parseFloat(terminal.rows[0].stampduty);

                agentamount = parseFloat(mainamount) + parseFloat(agentamount);
                var vatKar = ((parseFloat(vat) / 100) * parseFloat(karrabofee)).toFixed(2);
                var vatEtzn = ((parseFloat(vat) / 100) * parseFloat(terminal.rows[0].switchfee)).toFixed(2);
                
                var agentamount = parseFloat(amount) - parseFloat(karrabofee) - parseFloat(superagentfee) - vatKar - vatEtzn - usemsc - parseFloat(terminal.rows[0].switchfee) - stamp;
                
                if(parseFloat(agentamount) < 0)
                {
                    var qry3 = "INSERT INTO etranzactstatus " + 
                        "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                        "bankname, bankcode, accountnumber, status, transactiontype, karrabofee, superagentfee, ref)" + 
                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                    pool.query(qry3, ["AGENT AMOUNT NEGATIVE", rrn, "-1", 
                        "INVALID AGENT FEE", tid, amount, agentamount, "NA", 
                        terminal.rows[0].accountcode, terminal.rows[0].accountnumber, "ERROR OCCURRED", "CASH WITHDRAWAL", karrabofee, superagentfee], (err, resul) => {
                        if (err) 
                        {
                            logger.ingo(err);
                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "FEES DOES NOT TALLY"});
                        }else
                        {
                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "FEES DOES NOT TALLY"});
                        }
                    });
                }else 
                {
                    var qry2 = "INSERT INTO frometranzact " + 
                        "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                        "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                        "cnumberc, others, status, amount, agentamount, superagentamount, karraboamount, msc, switchfee, destination, tocustomer, stampduty)" + 
                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31)";
                    pool.query(qry2, ["", "", "", transRef, tid, "", "CASH WITHDRAWAL", terminal.rows[0].kaaccountnumber, terminal.rows[0].kaaccountcode, terminal.rows[0].kaaccountbank,
                        terminal.rows[0].kaaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                        terminal.rows[0].accountname, rrn, "DEBIT SUCCESS", amount, agentamount, superagentfee, karrabofee, usemsc, terminal.rows[0].switchfee, "", "0.00", stamp], (err, resul) => {
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
                            pool.query(qry3, [tid, "", agentamount, usemsc, rrn, stamp, terminal.rows[0].instantvaluepercentage,
                                terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                terminal.rows[0].accountbank, "NOT SETTLED", "agent" + tid], (err, resul) => {
                                if (err) 
                                {
                                    logger.info(err);
                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                }else
                                {
                                    var qry3 = "INSERT INTO agencyinstant " + 
                                        "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                        "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype" +
                                        ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                    pool.query(qry3, [tid, "", superagentfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                        terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                        terminal.rows[0].saaccountname, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountnumber,
                                        terminal.rows[0].saaccountbank, "NOT SETTLED", "superagent" + tid], (err, resul) => {
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
                                            pool.query(qry3, [tid, "", karrabofee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                                terminal.rows[0].kaaccountname, terminal.rows[0].kaaccountcode, terminal.rows[0].kaaccountnumber,
                                                terminal.rows[0].kaaccountbank, "NOT SETTLED", "karrabo" + tid], (err, resul) => {
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
                                                    pool.query(qry3, [tid, "", vatKar, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                        terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                                        "KARRABO VAT ACCOUNT", vatActCode, vatAct,
                                                        vatBank, "NOT SETTLED", "vat" + tid], (err, resul) => {
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
                    });
                }
            }
        }
    });
});

//VALIDATION - DONT SAVE
//get account/card/mobile phone information
//OKAY
router.get("/validateaccount", function(req, res) 
{
    var action = "AQ";
    var endpoint = req.headers.endpoint;//C or A or M
    var tid = karraboholdingtid;
    var rrn = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });
    var destination = req.headers.destination;//Account Number or Card Number or Mobile Number
    var bankcode = req.headers.bankcode;//Only compulsory for account
    var xml = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ws="http://ws.fundgate.etranzact.com/">
        <soapenv:Header/>
        <soapenv:Body>
        <ws:process>
            <request>
                <direction>request</direction>` +
                "<action>" + action + "</action>" + 
                "<terminalId>" + tid + "</terminalId>" +
                "<transaction>" +
                    "<pin>" + pin + "</pin>" +
                    "<destination>" + destination + "</destination>" +
                    "<bankCode>" + bankcode + "</bankCode>" +
                    "<amount>0.0</amount>" +
                    "<reference>" + rrn + "</reference>" +
                    "<endPoint>" + endpoint + "</endPoint>" +
                    "<terminalCard>false</terminalCard>" +
                `</transaction>
            </request>
        </ws:process>
        </soapenv:Body>
    </soapenv:Envelope>`
    
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
                var n1 = response.body.indexOf("<response>");
                var n2 = response.body.indexOf("</response>");
                var fn = response.body.slice(n1, n2 + 11);
                parseString(fn, {explicitArray: false}, function (err, result) {
                    if(err)
                    {
                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful 2x"});
                    }else
                    {
                        if(result.response.error === '0')
                            return res.header("Content-Type",'Application/json').status(200).send(result.response);
                        else
                            return res.header("Content-Type",'Application/json').status(500).send(result.response);
                    }
                });
            }else
                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful"});
        }
    });
});

//ACCOUNT TRANSFER/DEPOSIT
//debit merchant/agent account, credit karrabo holding
//OKAY
router.get("/creditcustomeraccount", function(req, res) 
{
    var tid = req.headers.tid;
    var bankcode = req.headers.bankcode;
    var destination = req.headers.destination;//Customer Account
    var amount = req.headers.amount.replace(/,/g, '');
    var mainamount = req.headers.mainamount.replace(/,/g, '');
    var fee = req.headers.fee.replace(/,/g, '');
    var bulkfee = req.headers.karrabofee;
    var superagentfee = req.headers.superagentfee;

    logger.info("CASH DEPOSIT / TRANSFER TO ACCOUNT");

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
                var usemsc = ((parseFloat(terminal.rows[0].msc) / 100) * parseFloat(amount)).toFixed(2);
                if(usemsc > 1000)
                    usemsc = 1000.00;
                
                var stamp = 0.00;
                if(parseFloat(amount) >= 10000)
                    stamp = parseFloat(terminal.rows[0].stampduty);
                

                var karrabofee = (parseFloat(bulkfee) - parseFloat(superagentfee) - usemsc - parseFloat(terminal.rows[0].switchfee)).toFixed(2) - stamp
                var agentamount = parseFloat(fee) - parseFloat(bulkfee);
                var toCus = mainamount; //To account

                //var agentamount = (parseFloat(amount) - parseFloat(mainamount) - parseFloat(karrabofee) - parseFloat(superagentfee) - usemsc - parseFloat(terminal.rows[0].switchfee)).toFixed(2) - stamp;
                
                /*logger.info("MSC: " + usemsc);
                logger.info("STAMP: " + stamp);
                logger.info("SWITCH FEE: " + terminal.rows[0].switchfee);
                logger.info("TO CUSTOMER: " + toCus);
                logger.info("TO AGENT: " + agentamount);
                logger.info("TO SUPERAGENT: " + superagentfee);
                logger.info("TO KARRABO: " + karrabofee);*/

                var qry2 = "INSERT INTO frometranzact " + 
                    "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                    "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                    "cnumberc, others, status, amount, agentamount, superagentamount, karraboamount, msc, switchfee, destination, tocustomer, stampduty)" + 
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31)";
                pool.query(qry2, ["KARRABO HOLDING", "KARRABO HOLDING", "NA", transRef, tid, "NA", "CASH DEPOSIT / TRANSFER", terminal.rows[0].kaaccountnumber, terminal.rows[0].kaaccountcode, terminal.rows[0].kaaccountbank,
                    terminal.rows[0].kaaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                    terminal.rows[0].accountname, rrn, "Debit Success", amount, agentamount, superagentfee, karrabofee, usemsc, terminal.rows[0].switchfee, destination, toCus, stamp], (err, resul) => {
                    if (err) 
                    {
                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                        res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                    }else
                    {
                        if(1)
                        {
                            var xml = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ws="http://ws.fundgate.etranzact.com/">
                                <soapenv:Header/>
                                <soapenv:Body>
                                <ws:process>
                                    <request>
                                        <direction>request</direction>` +
                                        "<action>" + "FT" + "</action>" + 
                                        "<terminalId>" + karraboholdingtid + "</terminalId>" +
                                        "<transaction>" +
                                            "<pin>" + pin + "</pin>" +
                                            "<bankCode>" + bankcode + "</bankCode>" +
                                            "<amount>" + toCus + "</amount>" +
                                            "<description>" + "KARRABO SETTLEMENT" + "</description>" +
                                            "<destination>" + destination + "</destination>" +
                                            "<reference>" + rrn + "</reference>" +
                                            "<senderName>" + "KARRABO CASH DEPOSIT" + "</senderName>" +
                                            "<endPoint>A</endPoint>" +
                                        `</transaction>
                                    </request>
                                </ws:process>
                                </soapenv:Body>
                            </soapenv:Envelope>`
                            
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
                                    var n1 = split.body.indexOf("<response>");
                                    var n2 = split.body.indexOf("</response>");
                                    var fn = split.body.slice(n1, n2 + 11);
                                    parseString(fn, {explicitArray: false}, function (err, result) {
                                        if(err)
                                        {
                                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful 2x"});
                                        }else
                                        {
                                            if(result.response.error == '0')
                                            {
                                                var qry3 = "INSERT INTO agencyinstant " + 
                                                    "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                    "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype" +
                                                    ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                pool.query(qry3, [tid, "", agentamount, usemsc, rrn, stamp, terminal.rows[0].instantvaluepercentage,
                                                    terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                                    terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                    terminal.rows[0].accountbank, "NOT SETTLED", "agent"+tid], (err, resul) => {
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
                                                        pool.query(qry3, [tid, "", superagentfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                            terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                                            terminal.rows[0].saaccountname, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountnumber,
                                                            terminal.rows[0].saaccountbank, "NOT SETTLED", "agent"+tid], (err, resul) => {
                                                            if (err) 
                                                            {
                                                                logger.info(err);
                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                            }else
                                                            {
                                                                var qry3 = "INSERT INTO agencyinstant " + 
                                                                    "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                    "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype" +
                                                                    ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                pool.query(qry3, [tid, "", karrabofee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                    terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                                                    terminal.rows[0].kaaccountname, terminal.rows[0].kaaccountcode, terminal.rows[0].kaaccountnumber,
                                                                    terminal.rows[0].kaaccountbank, "NOT SETTLED", "karrabo" + tid], (err, resul) => {
                                                                    if (err) 
                                                                    {
                                                                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                        res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                    }else
                                                                    {
                                                                        logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                        return res.header("Content-Type",'Application/json').status(200).send(result.response);
                                                                    }
                                                                });
                                                            }
                                                        });
                                                    }
                                                });
                                            }else
                                            {
                                                return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                            }
                                        }
                                    });
                                }
                            });
                        }else
                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful"});
                    }
                });
            }
        }
    });
});

//BALANCE ENQUIRY - DONT SAVE
//get Merchant/Agent Balance Enquiry
//OKAY
router.get("/balanceenquiry", function(req, res) 
{
    var action = "BE";
    var endpoint = "0";
    var tid = karraboholdingtid;
    var amount = "0.0";

    var rrn = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });

    var xml = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ws="http://ws.fundgate.etranzact.com/">
        <soapenv:Header/>
        <soapenv:Body>
        <ws:process>
            <request>
                <direction>request</direction>` +
                "<action>" + action + "</action>" + 
                "<terminalId>" + tid + "</terminalId>" +
                "<transaction>" +
                    "<pin>" + pin + "</pin>" +
                    "<amount>" + amount + "</amount>" +
                    "<reference>" + rrn + "</reference>" +
                    "<endPoint>" + endpoint + "</endPoint>" +
                    "<terminalCard>false</terminalCard>" +
                `</transaction>
            </request>
        </ws:process>
        </soapenv:Body>
    </soapenv:Envelope>`
    
    var clientServerOptions = {
        uri: wsdlURL,
        body: xml,
        method: 'POST',
        headers: {
            'Content-Type': 'text/xml;charset=UTF-8',
            //'Authorization': basic("ptsp_user8", "password")
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
            //logger.info(response.body);
            if(response.statusCode == 200)
            {
                var n1 = response.body.indexOf("<response>");
                var n2 = response.body.indexOf("</response>");
                var fn = response.body.slice(n1, n2 + 11);
                parseString(fn, {explicitArray: false}, function (err, result) {
                    if(err)
                    {
                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful 2x"});
                    }else
                    {
                        if(result.response.error === "0")
                            return res.header("Content-Type",'Application/json').status(200).send(result.response);
                        else
                            return res.header("Content-Type",'Application/json').status(500).send(result.response);
                    }
                });
            }else
                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful"});
        }
    });
});

//VTU CARD
//OKAY
router.get("/cardvtu", function(req, res) 
{
    var action = "VT";
    var endpoint = "0";
    var tid = req.headers.tid;
    var lineType = "VTU";
    var senderName = req.headers.sendername;
    var address = req.headers.address;
    var provider = req.headers.provider;
    var destination = req.headers.destination;//Phone Number to credit
    var amount = req.headers.amount.replace(/,/g, '');

    logger.info("VTU PAYMENT");
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
                var qry2 = "INSERT INTO toetranzact " + 
                    "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                    "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                    "cnumberc, others, status, amount)" + 
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)";
                pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "VTU", "NA", "NA", "",
                    "", "", "", "", "", "NA", "", "", "",
                    "", rrn, "Not Completed", amount], (err, resul) => {
                    if (err) 
                    {
                        console.log(err);
                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                        res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                    }else
                    {
                        var xml = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ws="http://ws.fundgate.etranzact.com/">
                            <soapenv:Header/>
                            <soapenv:Body>
                            <ws:process>
                                <request>
                                    <direction>request</direction>` +
                                    "<action>" + action + "</action>" + 
                                    "<terminalId>" + karraboholdingtid + "</terminalId>" +
                                    "<transaction>" +
                                        "<pin>" + pin + "</pin>" +
                                        "<provider>" + provider + "</provider>" +
                                        "<amount>" + amount + "</amount>" +
                                        "<lineType>" + lineType + "</lineType>" +
                                        "<senderName>" + senderName + "</senderName>" +
                                        "<address>" + address + "</address>" +
                                        "<destination>" + destination + "</destination>" +
                                        "<reference>" + rrn + "</reference>" +
                                        "<endPoint>" + endpoint + "</endPoint>" +
                                        "<terminalCard>false</terminalCard>" +
                                    `</transaction>
                                </request>
                            </ws:process>
                            </soapenv:Body>
                        </soapenv:Envelope>`
                        var clientServerOptions = {
                            uri: wsdlURL,
                            body: xml,
                            method: 'POST',
                            headers: {
                                'Content-Type': 'text/xml;charset=UTF-8',
                                //'Authorization': basic("ptsp_user8", "password")
                            }
                        }
                        //console.log(xml);
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
                                    var n1 = response.body.indexOf("<response>");
                                    var n2 = response.body.indexOf("</response>");
                                    var fn = response.body.slice(n1, n2 + 11);
                                    parseString(fn, {explicitArray: false}, function (err, result) {
                                        if(err)
                                        {
                                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful 2x"});
                                        }else
                                        {
                                            if(result.response.error === "0")
                                            {
                                                var qry2 = "INSERT INTO frometranzact " + 
                                                    "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                                    "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                                    "cnumberc, others, status, amount, agentamount, superagentamount, karraboamount, msc, switchfee, destination, tocustomer)" + 
                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)";
                                                pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "VTU", terminal.rows[0].kaaccountnumber, terminal.rows[0].kaaccountcode, terminal.rows[0].kaaccountbank,
                                                    terminal.rows[0].kaaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                    terminal.rows[0].accountname, transRef, "Transaction Success - CARD", amount, "0.00", "0.00", "0.00", "0.00", 
                                                    "0.00", destination + " - " + lineType + " - " + provider, "0.00"], (err, resul) => {
                                                    if (err) 
                                                    {
                                                        logger.info(err);
                                                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                        res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                    }else
                                                    {
                                                        var qry2 = "SELECT * FROM billsfee WHERE billername = $1";
                                                        pool.query(qry2, [provider], (err, bills) => {
                                                            if (err) 
                                                            {
                                                                logger.info("An error occurred");
                                                                logger.info(err);
                                                                return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
                                                            }else
                                                            {
                                                                var cfee = bills.rows[0].conveniencefee;
                                                                var netamount = amount - parseFloat(cfee);
                                                                var agentconfee = parseFloat(cfee) - parseFloat(bills.rows[0].agentconveniencefee);
                                                                var karraboconfee = parseFloat(cfee) - parseFloat(bills.rows[0].karraboconveniencefee);
                                                                logger.info("AGENT CONVENIENCE DUE: " + agentconfee);
                                                                logger.info("KARRABO CONVENIENCE DUE: " + karraboconfee);
                                                                var etranzactdue = parseFloat(cfee) - parseFloat(agentconfee) - parseFloat(karraboconfee);
                                                                logger.info("ETRANZACT CONVENIENCE DUE: " + etranzactdue);


                                                                var percentage = ((parseFloat(bills.rows[0].percentagedue) / 100) * parseFloat(netamount)).toFixed(2);
                                                                if(bills.rows[0].percentagecapped !== "0.00")
                                                                {
                                                                    if(percentage > parseFloat(bills.rows[0].percentagecapped))
                                                                        percentage = parseFloat(bills.rows[0].percentagecapped);
                                                                }
                                                                logger.info("PERCENTAGE: " + percentage);

                                                                var karrabopercentage = ((parseFloat(bills.rows[0].karrabopercentage) / 100) * parseFloat(percentage)).toFixed(2);
                                                                var agentpercentage = ((parseFloat(bills.rows[0].agentpercentage) / 100) * parseFloat(percentage)).toFixed(2);
                                                                logger.info("KARRABO PERCENTAGE: " + karrabopercentage);
                                                                logger.info("AGENT PERCENTAGE: " + agentpercentage);
                                                                
                                                                var creditAgent = parseFloat(agentconfee) + parseFloat(agentpercentage);
                                                                var creditKarrabo = parseFloat(karraboconfee) + parseFloat(karrabopercentage);

                                                                logger.info("CREDIT AGENT: " + creditAgent);
                                                                logger.info("CREDIT KARRABO: " + creditKarrabo);

                                                                var qry3 = "INSERT INTO agencyinstant " + 
                                                                    "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                    "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype" +
                                                                    ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                pool.query(qry3, [tid, "", creditAgent, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                    terminal.rows[0].instantvaluetime, "BILLS PAYMENT", 
                                                                    terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                                    terminal.rows[0].accountbank, "NOT SETTLED", "agent" + tid], (err, resul) => {
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
                                                                        pool.query(qry3, [tid, "", creditKarrabo, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                            terminal.rows[0].instantvaluetime, "BILLS PAYMENT", 
                                                                            terminal.rows[0].kaaccountname, terminal.rows[0].kaaccountcode, terminal.rows[0].kaaccountnumber,
                                                                            terminal.rows[0].kaaccountbank, "NOT SETTLED", "karrabo" + tid], (err, resul) => {
                                                                            if (err) 
                                                                            {
                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                            }else
                                                                            {
                                                                                logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                return res.header("Content-Type",'Application/json').status(200).send(result.response);
                                                                            }
                                                                        });
                                                                    }
                                                                });
                                                            }
                                                        });
                                                    }
                                                });
                                            }else
                                                return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                        }
                                    });
                                }else
                                    return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful"});
                            }
                        });
                    }
                });
            }
        }
    });
});

//validate the bills payment
//OKAY
router.get("/validatebills", function(req, res) 
{
    var action = "PB";
    var endpoint = "0";
    var tid = karraboholdingtid;
    var lineType = req.headers.linetype;//EG DSTV, PHCN
    var senderName = req.headers.sendername;
    var address = req.headers.address;
    var description = req.headers.description;
    var id = "1";//1 for Validation, 2 for Payment
    var destination = req.headers.destination;//Eg Dstv Card
    var amount = req.headers.amount.replace(/,/g, '');
    var rrn = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });
    logger.info("BILLS VALIDATION");
    var xml = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ws="http://ws.fundgate.etranzact.com/">
        <soapenv:Header/>
        <soapenv:Body>
        <ws:process>
            <request>
                <direction>request</direction>` +
                "<action>" + action + "</action>" + 
                "<terminalId>" + tid + "</terminalId>" +
                "<transaction>" +
                    "<pin>" + pin + "</pin>" +
                    "<id>" + id + "</id>" +
                    "<amount>" + amount + "</amount>" +
                    "<lineType>" + lineType + "</lineType>" +
                    "<senderName>" + senderName + "</senderName>" +
                    "<address>" + address + "</address>" +
                    "<description>" + description + "</description>" +
                    "<destination>" + destination + "</destination>" +
                    "<reference>" + rrn + "</reference>" +
                    "<endPoint>" + endpoint + "</endPoint>" +
                    "<terminalCard>false</terminalCard>" +
                `</transaction>
            </request>
        </ws:process>
        </soapenv:Body>
    </soapenv:Envelope>`
    
    var clientServerOptions = {
        uri: wsdlURL,
        body: xml,
        method: 'POST',
        headers: {
            'Content-Type': 'text/xml;charset=UTF-8',
            //'Authorization': basic("ptsp_user8", "password")
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
            //logger.info(response.body);
            if(response.statusCode == 200)
            {
                var n1 = response.body.indexOf("<response>");
                var n2 = response.body.indexOf("</response>");
                var fn = response.body.slice(n1, n2 + 11);
                parseString(fn, {explicitArray: false}, function (err, result) {
                    if(err)
                    {
                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful 2x"});
                    }else
                    {
                        if(result.response.error === "0")
                        {
                            //return res.header("Content-Type",'Application/json').status(200).send(result.response);
                            parseString(result.response.message, {explicitArray: false}, function (err, afterresult) {
                                if(err)
                                {
                                    return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                }else
                                {
                                    delete afterresult.BillVerification.BillProductLists;
                                    return res.header("Content-Type",'Application/json').status(200).send(afterresult.BillVerification);
                                }
                            });
                        }else
                            return res.header("Content-Type",'Application/json').status(500).send(result.response);
                    }
                });
            }else
                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful"});
        }
    });
});

//BILLS PAYMENT - CARD
//OKAY
router.get("/cardbillspayment", function(req, res) 
{
    var action = "PB";
    var endpoint = "0";
    var tid = req.headers.tid;
    var lineType = req.headers.linetype;//EG DSTV, PHCN
    var senderName = req.headers.sendername;
    var address = req.headers.address;
    var description = req.headers.description;
    var id = "2";//1 for Validation, 2 for Payment
    var destination = req.headers.destination;//Eg Dstv Card
    var amount = req.headers.amount.replace(/,/g, '');
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
                var qry2 = "INSERT INTO toetranzact " + 
                    "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                    "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                    "cnumberc, others, status, amount)" + 
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)";
                pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "BILLS PAYMENT", "NA", "NA", "",
                    "", "", "", "", "", "NA", "", "", "",
                    "", rrn, "Not Completed", amount], (err, resul) => {
                    if (err) 
                    {
                        console.log(err);
                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                        res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                    }else
                    {
                        logger.info("BILLS PAYMENT");
                        var xml = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ws="http://ws.fundgate.etranzact.com/">
                            <soapenv:Header/>
                            <soapenv:Body>
                            <ws:process>
                                <request>
                                    <direction>request</direction>` +
                                    "<action>" + action + "</action>" + 
                                    "<terminalId>" + karraboholdingtid + "</terminalId>" +
                                    "<transaction>" +
                                        "<pin>" + pin + "</pin>" +
                                        "<id>" + id + "</id>" +
                                        "<amount>" + amount + "</amount>" +
                                        "<lineType>" + lineType + "</lineType>" +
                                        "<senderName>" + senderName + "</senderName>" +
                                        "<address>" + address + "</address>" +
                                        "<description>" + description + "</description>" +
                                        "<destination>" + destination + "</destination>" +
                                        "<reference>" + rrn + "</reference>" +
                                        "<endPoint>" + endpoint + "</endPoint>" +
                                        "<terminalCard>false</terminalCard>" +
                                    `</transaction>
                                </request>
                            </ws:process>
                            </soapenv:Body>
                        </soapenv:Envelope>`
                        
                        var clientServerOptions = {
                            uri: wsdlURL,
                            body: xml,
                            method: 'POST',
                            headers: {
                                'Content-Type': 'text/xml;charset=UTF-8',
                                //'Authorization': basic("ptsp_user8", "password")
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
                                //logger.info(response.body);
                                if(response.statusCode == 200)
                                {
                                    var n1 = response.body.indexOf("<response>");
                                    var n2 = response.body.indexOf("</response>");
                                    var fn = response.body.slice(n1, n2 + 11);
                                    parseString(fn, {explicitArray: false}, function (err, result) {
                                        if(err)
                                        {
                                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful 2x"});
                                        }else
                                        {
                                            if(result.response.error === "0")
                                            {
                                                var qry2 = "INSERT INTO frometranzact " + 
                                                    "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                                    "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                                    "cnumberc, others, status, amount, agentamount, superagentamount, karraboamount, msc, switchfee, destination, tocustomer)" + 
                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)";
                                                pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "BILLSPAYMENT", terminal.rows[0].kaaccountnumber, terminal.rows[0].kaaccountcode, terminal.rows[0].kaaccountbank,
                                                    terminal.rows[0].kaaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                    terminal.rows[0].accountname, transRef, "Transaction Success - CARD", amount, "0.00", "0.00", "0.00", "0.00", 
                                                    "0.00", destination + " - " + lineType, "0.00"], (err, resul) => {
                                                    if (err) 
                                                    {
                                                        logger.info(err);
                                                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                        res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                    }else
                                                    {
                                                        var qry2 = "SELECT * FROM billsfee WHERE billername = $1";
                                                        pool.query(qry2, [lineType], (err, bills) => {
                                                            if (err) 
                                                            {
                                                                logger.info("An error occurred");
                                                                logger.info(err);
                                                                return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
                                                            }else
                                                            {
                                                                var cfee = bills.rows[0].conveniencefee;
                                                                var netamount = amount - parseFloat(cfee);
                                                                var agentconfee = parseFloat(cfee) - parseFloat(bills.rows[0].agentconveniencefee);
                                                                var karraboconfee = parseFloat(cfee) - parseFloat(bills.rows[0].karraboconveniencefee);
                                                                logger.info("AGENT CONVENIENCE DUE: " + agentconfee);
                                                                logger.info("KARRABO CONVENIENCE DUE: " + karraboconfee);
                                                                var etranzactdue = parseFloat(cfee) - parseFloat(agentconfee) - parseFloat(karraboconfee);
                                                                logger.info("ETRANZACT CONVENIENCE DUE: " + etranzactdue);


                                                                var percentage = ((parseFloat(bills.rows[0].percentagedue) / 100) * parseFloat(netamount)).toFixed(2);
                                                                if(bills.rows[0].percentagecapped !== "0.00")
                                                                {
                                                                    if(percentage > parseFloat(bills.rows[0].percentagecapped))
                                                                        percentage = parseFloat(bills.rows[0].percentagecapped);
                                                                }
                                                                logger.info("PERCENTAGE: " + percentage);

                                                                var karrabopercentage = ((parseFloat(bills.rows[0].karrabopercentage) / 100) * parseFloat(percentage)).toFixed(2);
                                                                var agentpercentage = ((parseFloat(bills.rows[0].agentpercentage) / 100) * parseFloat(percentage)).toFixed(2);
                                                                logger.info("KARRABO PERCENTAGE: " + karrabopercentage);
                                                                logger.info("AGENT PERCENTAGE: " + agentpercentage);
                                                                
                                                                var creditAgent = parseFloat(agentconfee) + parseFloat(agentpercentage);
                                                                var creditKarrabo = parseFloat(karraboconfee) + parseFloat(karrabopercentage);

                                                                logger.info("CREDIT AGENT: " + creditAgent);
                                                                logger.info("CREDIT KARRABO: " + creditKarrabo);

                                                                var qry3 = "INSERT INTO agencyinstant " + 
                                                                    "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                    "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype" +
                                                                    ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                pool.query(qry3, [tid, "", creditAgent, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                    terminal.rows[0].instantvaluetime, "BILLS PAYMENT", 
                                                                    terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                                    terminal.rows[0].accountbank, "NOT SETTLED", "agent" + tid], (err, resul) => {
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
                                                                        pool.query(qry3, [tid, "", creditKarrabo, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                            terminal.rows[0].instantvaluetime, "BILLS PAYMENT", 
                                                                            terminal.rows[0].kaaccountname, terminal.rows[0].kaaccountcode, terminal.rows[0].kaaccountnumber,
                                                                            terminal.rows[0].kaaccountbank, "NOT SETTLED", "karrabo" + tid], (err, resul) => {
                                                                            if (err) 
                                                                            {
                                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                            }else
                                                                            {
                                                                                logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                return res.header("Content-Type",'Application/json').status(200).send(result.response);
                                                                            }
                                                                        });
                                                                    }
                                                                });
                                                            }
                                                        });
                                                    }
                                                });
                                            }else
                                                return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                        }
                                    });
                                }else
                                    return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful"});
                            }
                        });
                    }
                });
            }
        }
    });
});

//Private api to move money
router.get("/fundtransfer", function(req, res) 
{
    var tid = req.headers.tid;
    var bankcode = req.headers.bankcode;
    var destination = req.headers.destination;//Customer Account
    var amount = req.headers.amount.replace(/,/g, '');
    var karrabofee = req.headers.karrabofee;
    var superagentfee = req.headers.superagentfee;

    logger.info("TRANSFER TO ACCOUNT");

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
                var usemsc = ((parseFloat(terminal.rows[0].msc) / 100) * parseFloat(amount)).toFixed(2);
                if(usemsc > 1000)
                    usemsc = 1000.00;
                var agentamount = (parseFloat(amount) - parseFloat(karrabofee) - parseFloat(superagentfee) - usemsc - parseFloat(terminal.rows[0].switchfee)).toFixed(2);
                var totalamount = (parseFloat(amount) - usemsc - parseFloat(terminal.rows[0].switchfee)).toFixed(2);
                var holding = agentamount % 1000;
                var toCus = (agentamount - holding).toFixed(2); //To account
                agentamount = holding.toFixed(2);
                
                var qry2 = "INSERT INTO frometranzact " + 
                    "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                    "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                    "cnumberc, others, status, amount, agentamount, superagentamount, karraboamount, msc, switchfee, destination, tocustomer)" + 
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)";
                pool.query(qry2, ["KARRABO HOLDING", "KARRABO HOLDING", "NA", transRef, tid, "NA", "CASH DEPOSIT / TRANSFER", terminal.rows[0].kaaccountnumber, terminal.rows[0].kaaccountcode, terminal.rows[0].kaaccountbank,
                    terminal.rows[0].kaaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                    terminal.rows[0].accountname, rrn, "Debit Success", amount, agentamount, superagentfee, karrabofee, usemsc, terminal.rows[0].switchfee, destination, toCus], (err, resul) => {
                    if (err) 
                    {
                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                        res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                    }else
                    {
                        if(1)
                        {
                            var xml = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ws="http://ws.fundgate.etranzact.com/">
                                    <soapenv:Header/>
                                    <soapenv:Body>
                                    <ws:process>
                                        <request>
                                            <direction>request</direction>` +
                                            "<action>" + "FT" + "</action>" + 
                                            "<terminalId>" + karraboholdingtid + "</terminalId>" + 
                                            "<transaction>" +
                                                "<pin>" + pin + "</pin>" +
                                                "<amount>" + toCus + "</amount>" +
                                                "<destination>" + destination + "</destination>" +
                                                "<bankCode>" + bankcode + "</bankCode>" +
                                                "<reference>" + rrn + "</reference>" +
                                                "<description>FROM KARRABO</description>" +
                                                "<senderName>KARRABO HOLDING</senderName>" +
                                                "<endPoint>A</endPoint>" +
                                            `</transaction>
                                        </request>
                                    </ws:process>
                                    </soapenv:Body>
                                </soapenv:Envelope>`

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
                                    var n1 = split.body.indexOf("<response>");
                                    var n2 = split.body.indexOf("</response>");
                                    var fn = split.body.slice(n1, n2 + 11);
                                    parseString(fn, {explicitArray: false}, function (err, result) {
                                        if(err)
                                        {
                                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful 2x"});
                                        }else
                                        {
                                            if(result.response.error == '0')
                                            {
                                                return res.header("Content-Type",'Application/json').status(200).send(result.response);
                                            }else
                                            {
                                                return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                            }
                                        }
                                    });
                                }
                            });
                        }else
                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful"});
                    }
                });
            }
        }
    });
});


module.exports.router = router;