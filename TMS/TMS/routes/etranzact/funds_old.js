var router = express.Router();
var request = require('request').defaults({ rejectUnauthorized: false })
const { join } = require('path');

//const wsdlURL = "https://demo.etranzact.com/FGate/ws?wsdl";//Test Ip
const wsdlURL = "https://www.etranzact.net/FGate/ws?wsdl";//Live Ip
//var pin = "kghxqwveJ3eSQJip/cmaMQ==";
var pin = "Ll2gQZMusI747Vo9K9T65w==";
var tmsholdingtid = "2140010002";
var tmscompanyid = "00000000000000000018";

//CASH WITHDRAWAL
//debit customer card, credit tms holding account
router.get("/cardtoaccount", function(req, res) 
{
    var tid = req.headers.tid;
    var amount = parseFloat(req.headers.amount.replace(/,/g, ''));
    var tmsfee = req.headers.tmsfee;
    var superagentfee = req.headers.superagentfee;

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

                var agentamount = parseFloat(amount) - parseFloat(tmsfee) - parseFloat(superagentfee) - usemsc - parseFloat(terminal.rows[0].switchfee) - stamp;
                var totalamount = parseFloat(amount) - usemsc - parseFloat(terminal.rows[0].switchfee) - stamp;
                
                var qry2 = "INSERT INTO frometranzact " + 
                    "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                    "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                    "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, stampduty)" + 
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31)";
                pool.query(qry2, ["", "", "", transRef, tid, "", "CASH WITHDRAWAL", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                    terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                    terminal.rows[0].accountname, rrn, "DEBIT SUCCESS", amount, agentamount, superagentfee, tmsfee, usemsc, terminal.rows[0].switchfee, "", "0.00", stamp], (err, resul) => {
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
                                        "<action>" + "BT" + "</action>" + 
                                        "<terminalId>" + tmsholdingtid + "</terminalId>" +
                                        "<transaction>" +
                                            "<companyId>" + tmscompanyid + "</companyId>" +
                                            "<pin>" + pin + "</pin>" +
                                            "<amount>" + totalamount + "</amount>" +
                                            "<reference>" + rrn + "</reference>" +
                                            "<senderName>tms HOLDING</senderName>" +
                                            "<endPoint>A</endPoint>" +
                                            //"<token>N</token>" +
                                            "<bulkItems>" +
                                                "<bulkItem>" +
                                                    "<uniqueId>" + transRef1 +"</uniqueId>" +
                                                    "<bankCode>" + terminal.rows[0].caaccountcode +"</bankCode>" + 
                                                    "<accountId>" + terminal.rows[0].caaccountnumber +"</accountId>" + 
                                                    "<beneficiaryName>" + terminal.rows[0].caaccountname + "</beneficiaryName>" +
                                                    "<narration>CASH WITHDRAWAL</narration>" +
                                                    "<amount>" + tmsfee + "</amount>" +
                                                "</bulkItem>" +
                                                "<bulkItem>" +
                                                    "<uniqueId>" + transRef2 +"</uniqueId>" +
                                                    "<bankCode>" + terminal.rows[0].saaccountcode +"</bankCode>" + 
                                                    "<accountId>" + terminal.rows[0].saaccountnumber +"</accountId>" + 
                                                    "<beneficiaryName>" + terminal.rows[0].saaccountname + "</beneficiaryName>" +
                                                    "<narration>CASH WITHDRAWAL</narration>" +
                                                    "<amount>" + superagentfee + "</amount>" +
                                                "</bulkItem>" +
                                                "<bulkItem>" +
                                                    "<uniqueId>" + transRef3 +"</uniqueId>" +
                                                    "<bankCode>" + terminal.rows[0].accountcode +"</bankCode>" + 
                                                    "<accountId>" + terminal.rows[0].accountnumber +"</accountId>" + 
                                                    "<beneficiaryName>" + terminal.rows[0].accountname + "</beneficiaryName>" +
                                                    "<narration>CASH WITHDRAWAL</narration>" +
                                                    "<amount>" + agentamount + "</amount>" +
                                                "</bulkItem>" +
                                            "</bulkItems>" +
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
                            request(clientServerOptions, function (error, split) {
                                if(error)
                                {
                                    logger.info(clientServerOptions);
                                    logger.info("ERROR: " + error);
                                    logger.info("SPLIT NOT SUCCESS");
                                    return res.header("Content-Type",'application/json').status(500).send(response.body);
                                }
                                if(split)
                                {
                                    logger.info(split.statusCode);
                                    logger.info("RESPONSE");
                                    if(split.statusCode == 200)
                                    {
                                        var n1 = split.body.indexOf("<response>");
                                        var n2 = split.body.indexOf("</response>");
                                        var fn = split.body.slice(n1, n2 + 11);
                                        parseString(fn, {explicitArray: false}, function (err, result) {
                                            if(err)
                                            {
                                                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful 2x"});
                                            }else
                                            {
                                                logger.info(result);
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
                        }else
                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful"});
                    }
                });
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
    var tid = tmsholdingtid;
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
//debit merchant/agent account, credit tms holding
//OKAY
router.get("/creditcustomeraccount", function(req, res) 
{
    var tid = req.headers.tid;
    var bankcode = req.headers.bankcode;
    var destination = req.headers.destination;//Customer Account
    var amount = req.headers.amount.replace(/,/g, '');
    var tmsfee = req.headers.tmsfee;
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
                
                var agentamount = (parseFloat(amount) - parseFloat(tmsfee) - parseFloat(superagentfee) - usemsc - parseFloat(terminal.rows[0].switchfee)).toFixed(2) - stamp;
                var totalamount = (parseFloat(amount) - usemsc - parseFloat(terminal.rows[0].switchfee)).toFixed(2) - stamp;
                
                var holding = agentamount % 1000;
                var toCus = (agentamount - holding).toFixed(2); //To account
                agentamount = holding.toFixed(2);
                
                var qry2 = "INSERT INTO frometranzact " + 
                    "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                    "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                    "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, stampduty)" + 
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31)";
                pool.query(qry2, ["tms HOLDING", "tms HOLDING", "NA", transRef, tid, "NA", "CASH DEPOSIT / TRANSFER", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                    terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                    terminal.rows[0].accountname, rrn, "Debit Success", amount, agentamount, superagentfee, tmsfee, usemsc, terminal.rows[0].switchfee, destination, toCus, stamp], (err, resul) => {
                    if (err) 
                    {
                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                        res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                    }else
                    {
                        if(1)
                        {
                            console.log("Total: " + totalamount);
                            console.log("tms Fee: " + tmsfee);
                            console.log("Superagent Fee: " + superagentfee);
                            console.log("Agent Share: " + agentamount);
                            console.log("To Customer: " + toCus);
                            console.log("MSC: " + usemsc);
                            console.log("STAMP: " + stamp);
                            var xml = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ws="http://ws.fundgate.etranzact.com/">
                                <soapenv:Header/>
                                <soapenv:Body>
                                <ws:process>
                                    <request>
                                        <direction>request</direction>` +
                                        "<action>" + "BT" + "</action>" + 
                                        "<terminalId>" + tmsholdingtid + "</terminalId>" +
                                        "<transaction>" +
                                            "<companyId>" + tmscompanyid + "</companyId>" +
                                            "<pin>" + pin + "</pin>" +
                                            "<amount>" + totalamount + "</amount>" +
                                            "<reference>" + rrn + "</reference>" +
                                            "<senderName>tms HOLDING</senderName>" +
                                            "<endPoint>A</endPoint>" +
                                            //"<token>N</token>" +
                                            "<bulkItems>" +
                                                "<bulkItem>" +
                                                    "<uniqueId>" + transRef1 +"</uniqueId>" +
                                                    "<accountId>" + terminal.rows[0].caaccountnumber +"</accountId>" + 
                                                    "<bankCode>" + terminal.rows[0].caaccountcode + "</bankCode>" + 
                                                    "<beneficiaryName>" + terminal.rows[0].caaccountname + "</beneficiaryName>" +
                                                    "<narration>CASH DEPOSIT</narration>" +
                                                    "<amount>" + tmsfee + "</amount>" +
                                                "</bulkItem>" +
                                                "<bulkItem>" +
                                                    "<uniqueId>" + transRef2 +"</uniqueId>" +
                                                    "<accountId>" + terminal.rows[0].saaccountnumber +"</accountId>" + 
                                                    "<bankCode>" + terminal.rows[0].saaccountcode +"</bankCode>" + 
                                                    "<beneficiaryName>" + terminal.rows[0].saaccountname + "</beneficiaryName>" +
                                                    "<narration>CASH DEPOSIT</narration>" +
                                                    "<amount>" + superagentfee + "</amount>" +
                                                "</bulkItem>" +
                                                "<bulkItem>" +
                                                    "<uniqueId>" + transRef3 +"</uniqueId>" +
                                                    "<accountId>" + terminal.rows[0].accountnumber +"</accountId>" + 
                                                    "<bankCode>" + terminal.rows[0].accountcode +"</bankCode>" + 
                                                    "<beneficiaryName>" + terminal.rows[0].accountname + "</beneficiaryName>" +
                                                    "<narration>CASH DEPOSIT</narration>" +
                                                    "<amount>" + agentamount + "</amount>" +
                                                "</bulkItem>" +
                                                "<bulkItem>" +
                                                    "<uniqueId>" + transRef4 +"</uniqueId>" +
                                                    "<accountId>" + destination +"</accountId>" +
                                                    "<bankCode>" + bankcode +"</bankCode>" + 
                                                    "<beneficiaryName>NA</beneficiaryName>" +
                                                    "<narration>CASH DEPOSIT</narration>" +
                                                    "<amount>" + toCus + "</amount>" +
                                                "</bulkItem>" +
                                            "</bulkItems>" +
                                        `</transaction>
                                    </request>
                                </ws:process>
                                </soapenv:Body>
                            </soapenv:Envelope>`
                            //console.log(xml);
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

//PHONE TRANSFER/DEPOSIT
//debit merchant/agent account, credit tms holding
//OKAY
router.get("/creditcustomerphone", function(req, res) 
{
    var tid = req.headers.tid;
    var destination = req.headers.destination;//PHONE NUMBER
    var amount = req.headers.amount.replace(/,/g, '');
    var tmsfee = req.headers.tmsfee;
    var superagentfee = req.headers.superagentfee;

    logger.info("CASH DEPOSIT / TRANSFER TO PHONE");

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

                var agentamount = (parseFloat(amount) - parseFloat(tmsfee) - parseFloat(superagentfee) - usemsc - parseFloat(terminal.rows[0].switchfee)).toFixed(2) - stamp;
                var holding = agentamount % 1000;
                var toCus = (agentamount - holding).toFixed(2); //To phone
                agentamount = holding.toFixed(2);
                var totalamount = (parseFloat(amount) - usemsc - parseFloat(terminal.rows[0].switchfee) - toCus).toFixed(2) - stamp;
                var qry2 = "INSERT INTO frometranzact " + 
                    "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                    "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                    "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, stampduty)" + 
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31)";
                pool.query(qry2, ["tms HOLDING", "tms HOLDING", "NA", transRef, tid, "NA", "CASH DEPOSIT / TRANSFER", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                    terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                    terminal.rows[0].accountname, rrn, "Debit Success", amount, agentamount, superagentfee, tmsfee, usemsc, terminal.rows[0].switchfee, destination, toCus.toString(), stamp], (err, resul) => {
                    if (err) 
                    {
                        logger.info(err);
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
                                        "<action>" + "BT" + "</action>" + 
                                        "<terminalId>" + tmsholdingtid + "</terminalId>" + 
                                        "<transaction>" +
                                            "<companyId>" + tmscompanyid + "</companyId>" +
                                            "<pin>" + pin + "</pin>" +
                                            "<amount>" + totalamount + "</amount>" +
                                            "<reference>" + rrn + "</reference>" +
                                            "<senderName>tms HOLDING</senderName>" +
                                            "<endPoint>A</endPoint>" +
                                            //"<token>N</token>" +
                                            "<bulkItems>" +
                                                "<bulkItem>" +
                                                    "<uniqueId>" + transRef1 +"</uniqueId>" +
                                                    "<accountId>" + terminal.rows[0].caaccountnumber +"</accountId>" + 
                                                    "<bankCode>" + terminal.rows[0].caaccountcode + "</bankCode>" + 
                                                    "<beneficiaryName>" + terminal.rows[0].caaccountname + "</beneficiaryName>" +
                                                    "<narration>CASH DEPOSIT</narration>" +
                                                    "<amount>" + tmsfee + "</amount>" +
                                                "</bulkItem>" +
                                                "<bulkItem>" +
                                                    "<uniqueId>" + transRef2 +"</uniqueId>" +
                                                    "<accountId>" + terminal.rows[0].saaccountnumber +"</accountId>" + 
                                                    "<bankCode>" + terminal.rows[0].saaccountcode +"</bankCode>" + 
                                                    "<beneficiaryName>" + terminal.rows[0].saaccountname + "</beneficiaryName>" +
                                                    "<narration>CASH DEPOSIT</narration>" +
                                                    "<amount>" + superagentfee + "</amount>" +
                                                "</bulkItem>" +
                                                "<bulkItem>" +
                                                    "<uniqueId>" + transRef3 +"</uniqueId>" +
                                                    "<accountId>" + terminal.rows[0].accountnumber +"</accountId>" + 
                                                    "<bankCode>" + terminal.rows[0].accountcode +"</bankCode>" + 
                                                    "<beneficiaryName>" + terminal.rows[0].accountname + "</beneficiaryName>" +
                                                    "<narration>CASH DEPOSIT</narration>" +
                                                    "<amount>" + agentamount + "</amount>" +
                                                "</bulkItem>" +
                                            "</bulkItems>" +
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

                            request(clientServerOptions, function (error, split) {
                                if(error)
                                {
                                    logger.info(clientServerOptions);
                                    logger.info("ERROR: " + error);
                                    logger.info("SPLIT NOT SUCCESS");
                                    return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                }
                                if(split)
                                {
                                    logger.info("BULK RESPONSE");
                                    logger.info(split.body);

                                    var endpoint = "M";
                                    xml = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ws="http://ws.fundgate.etranzact.com/">
                                        <soapenv:Header/>
                                        <soapenv:Body>
                                        <ws:process>
                                            <request>
                                                <direction>request</direction>` +
                                                "<action>" + "FT" + "</action>" + 
                                                "<terminalId>" + tid + "</terminalId>" + //tms Tid 
                                                "<transaction>" +
                                                    "<pin>" + pin + "</pin>" +
                                                    "<amount>" + toCus + "</amount>" +
                                                    "<destination>" + destination + "</destination>" +
                                                    "<reference>" + transRef4 + "</reference>" +
                                                    "<endPoint>" + endpoint + "</endPoint>" +
                                                    "<terminalCard>false</terminalCard>" +
                                                `</transaction>
                                            </request>
                                        </ws:process>
                                        </soapenv:Body>
                                    </soapenv:Envelope>`

                                    var n1 = split.body.indexOf("<response>");
                                    var n2 = split.body.indexOf("</response>");
                                    var fn = split.body.slice(n1, n2 + 11);
                                    parseString(fn, {explicitArray: false}, function (err, resultSplit) {
                                        if(err)
                                        {
                                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful 2x"});
                                        }else
                                        {
                                            if(resultSplit.response.error == '0')
                                            {
                                                clientServerOptions = {
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
                                                        logger.info(response.body);    
                                                        var n1 = response.body.indexOf("<response>");
                                                        var n2 = response.body.indexOf("</response>");
                                                        var fn = response.body.slice(n1, n2 + 11);
                                                        parseString(fn, {explicitArray: false}, function (err, resultSplit) {
                                                            if(err)
                                                            {
                                                                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful 2x"});
                                                            }else
                                                            {
                                                                logger.info(response.statusCode);
                                                                logger.info("RESPONSE");
                                                                if(response.statusCode == 200 && resultSplit.response.error == '0')
                                                                {
                                                                    return res.header("Content-Type",'Application/json').status(200).send(resultSplit.response);
                                                                }else
                                                                    return res.header("Content-Type",'Application/json').status(500).send(resultSplit.response);
                                                            }
                                                        });
                                                    }
                                                });
                                            }else
                                            {
                                                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful"});
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
    var tid = tmsholdingtid;
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

//VTU CASH
//Debit Customer So use Merchant Tid
//OKAY
router.get("/vtu", function(req, res) 
{
    var action = "VT";
    var endpoint = "0";
    var tid = req.headers.tid;
    //var lineType = req.headers.linetype;
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
                                    "<terminalId>" + tid + "</terminalId>" +
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
                                                    "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer)" + 
                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)";
                                                pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "VTU", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                                    terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                    terminal.rows[0].accountname, transRef, "Transaction Success - CASH", amount, "0.00", "0.00", "0.00", "0.00", 
                                                    "0.00", destination + " - " + lineType + " - " + provider, "0.00"], (err, resul) => {
                                                    if (err) 
                                                    {
                                                        logger.info(err);
                                                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                        res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                    }else
                                                    {
                                                        return res.header("Content-Type",'Application/json').status(200).send(result.response);
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

//VTU CARD
//OKAY
router.get("/cardvtu", function(req, res) 
{
    var action = "VT";
    var endpoint = "0";
    var tid = req.headers.tid;
    //var lineType = req.headers.linetype;
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
                                    "<terminalId>" + tmsholdingtid + "</terminalId>" +
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
                                                    "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer)" + 
                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)";
                                                pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "VTU", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                                    terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                    terminal.rows[0].accountname, transRef, "Transaction Success - CARD", amount, "0.00", "0.00", "0.00", "0.00", 
                                                    "0.00", destination + " - " + lineType + " - " + provider, "0.00"], (err, resul) => {
                                                    if (err) 
                                                    {
                                                        logger.info(err);
                                                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                        res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                    }else
                                                    {
                                                        return res.header("Content-Type",'Application/json').status(200).send(result.response);
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
    var tid = tmsholdingtid;
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

//BILLS PAYMENT - CASH
//OKAY
router.get("/billspayment", function(req, res) 
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
                                                var qry2 = "INSERT INTO frometranzact " + 
                                                    "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                                    "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                                    "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer)" + 
                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)";
                                                pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "BILLSPAYMENT", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                                    terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                    terminal.rows[0].accountname, transRef, "Transaction Success - CASH", amount, "0.00", "0.00", "0.00", "0.00", 
                                                    "0.00", destination + " - " + lineType, "0.00"], (err, resul) => {
                                                    if (err) 
                                                    {
                                                        logger.info(err);
                                                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                        res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                    }else
                                                    {
                                                        return res.header("Content-Type",'Application/json').status(200).send(result.response);
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
                                    "<terminalId>" + tmsholdingtid + "</terminalId>" +
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
                                                    "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer)" + 
                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)";
                                                pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "BILLSPAYMENT", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                                    terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                    terminal.rows[0].accountname, transRef, "Transaction Success - CARD", amount, "0.00", "0.00", "0.00", "0.00", 
                                                    "0.00", destination + " - " + lineType, "0.00"], (err, resul) => {
                                                    if (err) 
                                                    {
                                                        logger.info(err);
                                                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                        res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                    }else
                                                    {
                                                        return res.header("Content-Type",'Application/json').status(200).send(result.response);
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
    var tmsfee = req.headers.tmsfee;
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
                var agentamount = (parseFloat(amount) - parseFloat(tmsfee) - parseFloat(superagentfee) - usemsc - parseFloat(terminal.rows[0].switchfee)).toFixed(2);
                var totalamount = (parseFloat(amount) - usemsc - parseFloat(terminal.rows[0].switchfee)).toFixed(2);
                var holding = agentamount % 1000;
                var toCus = (agentamount - holding).toFixed(2); //To account
                agentamount = holding.toFixed(2);
                
                var qry2 = "INSERT INTO frometranzact " + 
                    "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                    "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                    "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer)" + 
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)";
                pool.query(qry2, ["tms HOLDING", "tms HOLDING", "NA", transRef, tid, "NA", "CASH DEPOSIT / TRANSFER", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                    terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                    terminal.rows[0].accountname, rrn, "Debit Success", amount, agentamount, superagentfee, tmsfee, usemsc, terminal.rows[0].switchfee, destination, toCus], (err, resul) => {
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
                                            "<terminalId>" + tmsholdingtid + "</terminalId>" + 
                                            "<transaction>" +
                                                "<pin>" + pin + "</pin>" +
                                                "<amount>" + toCus + "</amount>" +
                                                "<destination>" + destination + "</destination>" +
                                                "<bankCode>" + bankcode + "</bankCode>" +
                                                "<reference>" + rrn + "</reference>" +
                                                "<description>FROM tms</description>" +
                                                "<senderName>tms HOLDING</senderName>" +
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

//get all billers
//NOT YET AVAILABLE
router.get("/getbillers", function(req, res) 
{
    var action = "BI";
    var endpoint = "0";
    var tid = tmsholdingtid;
    var rrn = req.headers.rrn;
    var amount = "0.0";

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
                        return res.header("Content-Type",'Application/json').status(200).send(result.response);
                    }
                });
            }else
                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful"});
        }
    });
});

//get bank list
//Convert to bankname-code###
//NOT YET AVAILABLE
router.get("/allbanklist", function(req, res) 
{
    var action = "BL";
    var endpoint = "0";
    var tid = tmsholdingtid;
    var rrn = req.headers.rrn;
    var amount = "0.0";

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
                        return res.header("Content-Type",'Application/json').status(200).send(result.response);
                    }
                });
            }else
                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction was not successful"});
        }
    });
});

//tms Web Integration
//get settlement based on tid
//NOT YET AVAILABLE
router.get("/viewsettlement", function(req, res) 
{
    var rrn = randomstring.generate({
        length: 11,
        charset: 'numeric'
    });
    var action = "DS";
    var endpoint = "0";
    var tid = tmsholdingtid;
    var statementDate = req.headers.statementdate;//Start Date

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
                    "<statementDate>" + statementDate + "</statementDate>" +
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

//go to terminal
//Download bank list (optional)
//Download billers
    //Balance Enquiry
    //Paybills
    //cash deposit
        //cash
            //Validate first
            //debit agent (total) and credit tms holding
            //debit tms holding (amount - msc) and credit tms (fee based on rule), super-agent (fee based on rule), customer account (base amount), agent (commission)
        //card - cash is presented
            //Validate first
            //debit agent (total) and credit tms holding
            //debit tms holding (amount - msc) and credit tms (fee based on rule), super-agent (fee based on rule), customer card (base amount), agent (commission)
        //account - cash is presented
            //Validate first
            //debit agent (total) and credit tms holding
            //debit tms holding (amount - msc) and credit tms (fee based on rule), super-agent (fee based on rule), customer account (base amount), agent (commission)
        //phone - cash is presented
            //Validate first
            //debit agent (total) and credit tms holding
            //debit tms holding (amount - msc) and credit tms (fee based on rule), super-agent (fee based on rule), customer phone number (base amount), agent (commission)
    //cash transfer
        //cash
            //Validate first
            //debit agent (total) and credit tms holding
            //debit tms holding (amount - msc) and credit tms (fee based on rule), super-agent (fee based on rule), customer account (base amount), agent (commission)
        //card
            //Validate first
            //debit cardholder and credit tms holding
            //debit tms holding (amount - msc) and credit tms (fee based on rule), super-agent (fee based on rule), customer account (base amount), agent (commission)
    //cash withdrawal
        //card
            //Validate first
            //debit cardholder and credit tms holding
            //debit tms holding (amount - msc) and credit tms (fee based on rule), super-agent (fee based on rule), agent (balance)
        
module.exports.router = router;