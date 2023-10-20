var router = express.Router();
var request = require('request').defaults({ rejectUnauthorized: false })
const { join } = require('path');


const wsdlURL = "https://www.etranzact.net/FGate/ws?wsdl";//Live Ip
var pin = "Ll2gQZMusI747Vo9K9T65w==";
var tmsholdingtid = "2140010002";
var vat = "7.5";

var tmsbulktid = "2140010003";
var tmsbulkpin = "GOyfnSvqGSpflC3nfHCuDg==";
var tmscompanyid = "00000000000000000018";

var vatAct = "0122814626";
var vatActCode = "035";
var vatBank = "WEMA BANK";

//CASH WITHDRAWAL
//debit customer card, credit tms holding account
router.get("/cardtoaccount", function(req, res) 
{
    var tid = req.headers.tid;
    var amount = parseFloat(req.headers.amount.replace(/,/g, ''));
    var tmsfee = req.headers.tmsfee;
    var superagentfee = req.headers.superagentfee;
    var mainamount = req.headers.mainamount.replace(/,/g, '');
    var rrn = req.headers.rrn;
    var fee = req.headers.fee;

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

                var vatKar = 0.00;
                var etzn = 0.00;
                var vatEtzn = 0.00;
                var agentamount = 0.00;

                if(terminal.rows[0].percentagerule === "true")
                {
                    var kar = ((parseFloat(tmsfee) / 100) * parseFloat(fee)).toFixed(2);
                    var sup = ((parseFloat(superagentfee) / 100) * parseFloat(fee)).toFixed(2);

                    vatKar = ((parseFloat(vat) / 100) * parseFloat(kar)).toFixed(2);
                    tmsfee = parseFloat(kar) - parseFloat(vatKar) - parseFloat(stamp);
                    superagentfee = sup;
                    
                    etzn = 0.00;
                    vatEtzn = 0.00;

                    agentamount = parseFloat(amount) - parseFloat(tmsfee) - 
                        parseFloat(superagentfee) - parseFloat(vatKar) - parseFloat(vatEtzn) - parseFloat(usemsc) 
                        - parseFloat(etzn) - parseFloat(stamp);
                }else
                {
                    vatKar = ((parseFloat(vat) / 100) * parseFloat(tmsfee)).toFixed(2);
                    vatEtzn = ((parseFloat(vat) / 100) * parseFloat(terminal.rows[0].switchfee)).toFixed(2);
                    agentamount = parseFloat(amount) - parseFloat(tmsfee) - parseFloat(superagentfee) - vatKar - vatEtzn - usemsc - parseFloat(terminal.rows[0].switchfee) - stamp;
                
                }

                if(parseFloat(agentamount) < 0)
                {
                    var qry3 = "INSERT INTO etranzactstatus " + 
                        "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                        "bankname, bankcode, accountnumber, status, transactiontype, tmsfee, superagentfee, ref)" + 
                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                    pool.query(qry3, ["AGENT AMOUNT NEGATIVE", rrn, "-1", 
                        "INVALID AGENT FEE", tid, amount, agentamount, "NA", 
                        terminal.rows[0].accountcode, terminal.rows[0].accountnumber, "ERROR OCCURRED", "CASH WITHDRAWAL", tmsfee, superagentfee], (err, resul) => {
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
                        "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, stampduty, mainamount, fee, vatkar, varetzn, ref)" + 
                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36)";
                    pool.query(qry2, ["", "", "", rrn, tid, "", "CASH WITHDRAWAL", terminal.rows[0].caaccountnumber, 
                        terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                        terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, 
                        terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, 
                        rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                        terminal.rows[0].accountname, transRef, "DEBIT SUCCESS", amount, agentamount, superagentfee, 
                        tmsfee, usemsc, terminal.rows[0].switchfee, "NA", "0.00", stamp, mainamount, fee, vatKar, vatEtzn, rrn], (err, resul) => {
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
                                            pool.query(qry3, [tid, "", tmsfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                terminal.rows[0].instantvaluetime, "CASH WITHDRAWAL", 
                                                terminal.rows[0].caaccountname, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountnumber,
                                                terminal.rows[0].caaccountbank, "NOT SETTLED", "tms" + tid], (err, resul) => {
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
                                                        "tms VAT ACCOUNT", vatActCode, vatAct,
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

//ACCOUNT DEPOSIT
//debit merchant/agent account, credit tms holding
//OKAY
router.get("/depositcash", function(req, res) 
{
    var tid = req.headers.tid;
    var bankcode = req.headers.bankcode;
    var destination = req.headers.destination;//Customer Account
    var amount = req.headers.amount.replace(/,/g, '');
    var mainamount = req.headers.mainamount.replace(/,/g, '');
    var fee = req.headers.fee.replace(/,/g, '');
    var tmsfee = req.headers.tmsfee;
    var superagentfee = req.headers.superagentfee;
    var description = req.headers.description;
    var termRef = req.headers.rrn;

    logger.info("CASH DEPOSIT / TRANSFER TO ACCOUNT");
    logger.info(req.headers);

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
                
                var vatKar = ((parseFloat(vat) / 100) * parseFloat(tmsfee)).toFixed(2);
                var vatEtzn = ((parseFloat(vat) / 100) * parseFloat(terminal.rows[0].switchfee)).toFixed(2);
                
                //var agentamount = (parseFloat(amount) - parseFloat(mainamount) - parseFloat(tmsfee) - parseFloat(superagentfee) - vatKar - vatEtzn - usemsc - parseFloat(terminal.rows[0].switchfee)).toFixed(2) - stamp;
                var agentamount = (parseFloat(fee) - parseFloat(tmsfee) - parseFloat(superagentfee) - parseFloat(vatKar) - parseFloat(vatEtzn) - parseFloat(usemsc) - parseFloat(terminal.rows[0].switchfee)).toFixed(2) - parseFloat(stamp);
                var toCus = mainamount; //To account

                var Tfees = parseFloat(agentamount) + parseFloat(tmsfee) + parseFloat(superagentfee) + parseFloat(vatKar) + parseFloat(vatEtzn) + parseFloat(usemsc) + parseFloat(terminal.rows[0].switchfee) + parseFloat(stamp);
                if(parseFloat(agentamount) < 0)
                {
                    var qry3 = "INSERT INTO etranzactstatus " + 
                        "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                        "bankname, bankcode, accountnumber, status, transactiontype, tmsfee, superagentfee, ref)" + 
                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                    pool.query(qry3, ["AGENT FEE NEGATIVE", termRef, "-1", 
                        "INVALID AGENT FEE", tid, amount, toCus, "NA", 
                        bankcode, destination, "ERROR OCCURRED", "CASH DEPOSIT/TRANSFER", 
                        tmsfee, superagentfee, termRef], (err, resul) => {
                        if (err) 
                        {
                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "FEES DOES NOT TALLY"});
                        }else
                        {
                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "FEES DOES NOT TALLY"});
                        }
                    });
                }else
                {
                    var totalBulk = (parseFloat(tmsfee) + parseFloat(superagentfee) + parseFloat(toCus) + parseFloat(vatKar) + parseFloat(agentamount)).toFixed(2);
                    //tmsfee = (parseFloat(tmsfee) + parseFloat(agentamount)).toFixed(2);
                    var xml = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ws="http://ws.fundgate.etranzact.com/">
                        <soapenv:Header/>
                        <soapenv:Body>
                        <ws:process>
                            <request>
                                <direction>request</direction>` +
                                "<action>" + "BT" + "</action>" + 
                                "<terminalId>" + tmsbulktid + "</terminalId>" +
                                "<transaction>" +
                                    "<companyId>" + tmscompanyid + "</companyId>" +
                                    "<pin>" + tmsbulkpin + "</pin>" +
                                    "<amount>" + totalBulk + "</amount>" +
                                    "<reference>" + rrn + "</reference>" +
                                    "<endPoint>A</endPoint>" +
                                    "<senderName>" + description + "-" + tid + "-" + termRef + "</senderName>" +
                                    "<token>N</token>" +
                                    "<bulkItems>" +
                                        "<bulkItem>" +
                                            //tms Share
                                            "<uniqueId>" + transRef1 +"</uniqueId>" +
                                            "<accountId>" + terminal.rows[0].caaccountnumber +"</accountId>" + 
                                            "<bankCode>" + terminal.rows[0].caaccountcode + "</bankCode>" + 
                                            "<beneficiaryName>" + terminal.rows[0].caaccountname + "</beneficiaryName>" +
                                            "<narration>CASH DEPOSIT " + description + "-" + tid + "-" + termRef + "</narration>" +
                                            "<amount>" + tmsfee + "</amount>" +
                                        "</bulkItem>" +
                                        "<bulkItem>" +
                                            //Agent Share
                                            "<uniqueId>" + transRef6 +"</uniqueId>" +
                                            "<accountId>" + terminal.rows[0].accountnumber +"</accountId>" + 
                                            "<bankCode>" + terminal.rows[0].accountcode +"</bankCode>" + 
                                            "<beneficiaryName>" + terminal.rows[0].accountname + "</beneficiaryName>" +
                                            "<narration>" + "CASH DEPOSIT " + description + "-" + tid + "-" + termRef +"</narration>" +
                                            "<amount>" + agentamount + "</amount>" +
                                        "</bulkItem>" +

                                        "<bulkItem>" +
                                            //SuperAgent Share
                                            "<uniqueId>" + transRef2 +"</uniqueId>" +
                                            "<accountId>" + terminal.rows[0].saaccountnumber +"</accountId>" + 
                                            "<bankCode>" + terminal.rows[0].saaccountcode +"</bankCode>" + 
                                            "<beneficiaryName>" + terminal.rows[0].saaccountname + "</beneficiaryName>" +
                                            "<narration>CASH DEPOSIT " + description + "-" + tid + "-" + termRef + "</narration>" +
                                            "<amount>" + superagentfee + "</amount>" +
                                        "</bulkItem>" +
                                        "<bulkItem>" +
                                            //Customer Share
                                            "<uniqueId>" + transRef4 +"</uniqueId>" +
                                            "<accountId>" + destination +"</accountId>" +
                                            "<bankCode>" + bankcode +"</bankCode>" + 
                                            "<beneficiaryName>NA</beneficiaryName>" +
                                            "<narration>CASH DEPOSIT " + description + "-" + tid + "-" + termRef + "</narration>" +
                                            "<amount>" + toCus + "</amount>" +
                                        "</bulkItem>" +
                                        "<bulkItem>" +
                                            //VAT
                                            "<uniqueId>" + transRef5 +"</uniqueId>" +
                                            "<accountId>" + vatAct +"</accountId>" +
                                            "<bankCode>" + vatActCode +"</bankCode>" + 
                                            "<beneficiaryName>NA</beneficiaryName>" +
                                            "<narration>VAT " + description + "-" + tid + "-" + termRef + "</narration>" +
                                            "<amount>" + vatKar + "</amount>" +
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
                                        var qry2 = "INSERT INTO frometranzact " + 
                                            "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                            "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                            "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, stampduty, vatkar, varetzn, etranzactresponse, etranzactecho, mainamount, fee, ref)" + 
                                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38)";
                                        pool.query(qry2, ["tms HOLDING", "tms HOLDING", "NA", transRef, tid, "NA", "CASH DEPOSIT / TRANSFER", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                            terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                            terminal.rows[0].accountname, rrn, "Debit Success", amount, agentamount, superagentfee, tmsfee, usemsc, terminal.rows[0].switchfee, destination, toCus, stamp, vatKar, vatEtzn, result.response.message, result.response, mainamount, fee, termRef], (err, resul) => {
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
                                                pool.query(qry3, [tid, "", vatKar, usemsc, rrn, stamp, terminal.rows[0].instantvaluepercentage,
                                                    terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                    terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                    terminal.rows[0].accountbank, "SETTLED", "vat" + tid, termRef], (err, resul) => {
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
                                                        pool.query(qry3, [tid, "", superagentfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                            terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                            terminal.rows[0].saaccountname, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountnumber,
                                                            terminal.rows[0].saaccountbank, "SETTLED", "superagent"+tid, termRef], (err, resul) => {
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
                                                                    terminal.rows[0].caaccountbank, "SETTLED", "tms" + tid, termRef], (err, resul) => {
                                                                    if (err) 
                                                                    {
                                                                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                        res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                    }else
                                                                    {
                                                                        //tms, SUPER AGENT, AGENT AND VAT
                                                                        var qry8 = "INSERT INTO agentsettlement " + 
                                                                            "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                        pool.query(qry8, [tid, tmsfee, terminal.rows[0].caaccountbank, 
                                                                            terminal.rows[0].caaccountcode, terminal.rows[0].caaccountname, 
                                                                            terminal.rows[0].caaccountnumber, description + " - " + result.response.reference, termRef], (err, resul) => {
                                                                            if (err) 
                                                                            {
                                                                                logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                return res.header("Content-Type",'Application/json').status(200).send(result.response);
                                                                            }else
                                                                            {
                                                                                var qry9 = "INSERT INTO agentsettlement " + 
                                                                                    "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                pool.query(qry9, [tid, superagentfee, terminal.rows[0].saaccountbank, 
                                                                                    terminal.rows[0].saaccountcode, terminal.rows[0].saaccountname, 
                                                                                    terminal.rows[0].saaccountnumber, description + " - " + result.response.reference, termRef], (err, resul) => {
                                                                                    if (err) 
                                                                                    {
                                                                                        logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                        logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                        return res.header("Content-Type",'Application/json').status(200).send(result.response);
                                                                                    }else
                                                                                    {
                                                                                        var qry10 = "INSERT INTO agentsettlement " + 
                                                                                            "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                        pool.query(qry10, [tid, toCus, "NA", 
                                                                                            bankcode, "NA", 
                                                                                            destination, description + " - " + result.response.reference, termRef], (err, resul) => {
                                                                                            if (err) 
                                                                                            {
                                                                                                logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                                logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                return res.header("Content-Type",'Application/json').status(200).send(result.response);
                                                                                            }else
                                                                                            {
                                                                                                var qry11 = "INSERT INTO agentsettlement " + 
                                                                                                    "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                                pool.query(qry11, [tid, vatKar, vatBank, 
                                                                                                    vatActCode, "tms VAT ACCOUNT", vatAct, description + " - " + result.response.reference, termRef], (err, resul) => {
                                                                                                    if (err) 
                                                                                                    {
                                                                                                        logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                                        logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                        return res.header("Content-Type",'Application/json').status(200).send(result.response);
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
                                            "bankname, bankcode, accountnumber, status, transactiontype, tmsfee, superagentfee, ref)" + 
                                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                        pool.query(qry3, [result.response.message, result.response.otherReference, result.response.error, 
                                            result.response, tid, amount, toCus, "NA", 
                                            bankcode, destination, "ERROR OCCURRED", "CASH DEPOSIT/TRANSFER", tmsfee, superagentfee], (err, resul) => {
                                            if (err) 
                                            {
                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                            }else
                                            {
                                                var mailOptions = {
                                                    from: emailHeading, // sender address
                                                    to: "commercial@tms.com, abigail.owobrenu@tms.com, anthony.akinajo@tms.com", // list of receivers
                                                    replyTo: replyTo,
                                                    subject: "CASH DEPOSIT FAILURE", // Subject line
                                                    text: "ETRANZACT FAILED WITH \n" + JSON.stringify(result.response) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                };
                                                    
                                                transporter.sendMail(mailOptions, function(error, info){
                                                    if (error) {
                                                        return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                                    } else {
                                                        return res.header("Content-Type",'Application/json').status(500).send(result.response);
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
    });
});

//ACCOUNT TRANSFER
//debit merchant/agent account, credit tms holding
//OKAY
router.get("/cashtransfer", function(req, res) 
{
    var tid = req.headers.tid;
    var bankcode = req.headers.bankcode;
    var destination = req.headers.destination;//Customer Account
    var amount = req.headers.amount.replace(/,/g, '');
    var mainamount = req.headers.mainamount.replace(/,/g, '');
    var fee = req.headers.fee.replace(/,/g, '');
    var tmsfee = req.headers.tmsfee;
    var superagentfee = req.headers.superagentfee;
    var description = req.headers.description;
    var termRef = req.headers.rrn;

    logger.info("CASH DEPOSIT / TRANSFER TO ACCOUNT");
    logger.info(req.headers);

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
                
                var vatKar = ((parseFloat(vat) / 100) * parseFloat(tmsfee)).toFixed(2);
                var vatEtzn = ((parseFloat(vat) / 100) * parseFloat(terminal.rows[0].switchfee)).toFixed(2);
             
                var agentamount = (parseFloat(amount) - parseFloat(mainamount) - parseFloat(tmsfee) - parseFloat(superagentfee) - vatKar - vatEtzn - usemsc - parseFloat(terminal.rows[0].switchfee)).toFixed(2) - stamp;
                var toCus = mainamount; //To account
                var Tfees = parseFloat(agentamount) + parseFloat(tmsfee) + parseFloat(superagentfee) + parseFloat(vatKar) + parseFloat(vatEtzn) + parseFloat(usemsc) + parseFloat(terminal.rows[0].switchfee) + parseFloat(stamp);
                
                if(parseFloat(agentamount) < 0)
                {
                    var qry3 = "INSERT INTO etranzactstatus " + 
                        "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                        "bankname, bankcode, accountnumber, status, transactiontype, tmsfee, superagentfee, ref)" + 
                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                    pool.query(qry3, ["AGENT FEE NEGATIVE", termRef, "-1", 
                        "INVALID AGENT FEE", tid, amount, toCus, "NA", 
                        bankcode, destination, "ERROR OCCURRED", "CASH DEPOSIT/TRANSFER", 
                        tmsfee, superagentfee, termRef], (err, resul) => {
                        if (err) 
                        {
                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "FEES DOES NOT TALLY"});
                        }else
                        {
                            return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "FEES DOES NOT TALLY"});
                        }
                    });
                }else
                {
                    var totalBulk = (parseFloat(tmsfee) + parseFloat(superagentfee) + parseFloat(toCus) + parseFloat(vatKar) + parseFloat(agentamount)).toFixed(2);
                    tmsfee = (parseFloat(tmsfee) + parseFloat(agentamount)).toFixed(2);

                    agentamount = "0.00";
                    
                    var xml = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ws="http://ws.fundgate.etranzact.com/">
                        <soapenv:Header/>
                        <soapenv:Body>
                        <ws:process>
                            <request>
                                <direction>request</direction>` +
                                "<action>" + "BT" + "</action>" + 
                                "<terminalId>" + tmsbulktid + "</terminalId>" +
                                "<transaction>" +
                                    "<companyId>" + tmscompanyid + "</companyId>" +
                                    "<pin>" + tmsbulkpin + "</pin>" +
                                    "<amount>" + totalBulk + "</amount>" +
                                    "<reference>" + rrn + "</reference>" +
                                    "<endPoint>A</endPoint>" +
                                    "<senderName>" + description + "</senderName>" +
                                    "<token>N</token>" +
                                    "<bulkItems>" +
                                        "<bulkItem>" +
                                            //tms Share
                                            "<uniqueId>" + transRef1 +"</uniqueId>" +
                                            "<accountId>" + terminal.rows[0].caaccountnumber +"</accountId>" + 
                                            "<bankCode>" + terminal.rows[0].caaccountcode + "</bankCode>" + 
                                            "<beneficiaryName>" + terminal.rows[0].caaccountname + "</beneficiaryName>" +
                                            "<narration>ACCOUNT TRANSFER " + description + "-" + tid + "-" + termRef + "</narration>" +
                                            "<amount>" + tmsfee + "</amount>" +
                                        "</bulkItem>" +
                                        "<bulkItem>" +
                                            //SuperAgent Share
                                            "<uniqueId>" + transRef2 +"</uniqueId>" +
                                            "<accountId>" + terminal.rows[0].saaccountnumber +"</accountId>" + 
                                            "<bankCode>" + terminal.rows[0].saaccountcode +"</bankCode>" + 
                                            "<beneficiaryName>" + terminal.rows[0].saaccountname + "</beneficiaryName>" +
                                            "<narration>ACCOUNT TRANSFER " + description + "-" + tid + "-" + termRef + "</narration>" +
                                            "<amount>" + superagentfee + "</amount>" +
                                        "</bulkItem>" +
                                        "<bulkItem>" +
                                            //Customer Share
                                            "<uniqueId>" + transRef4 +"</uniqueId>" +
                                            "<accountId>" + destination +"</accountId>" +
                                            "<bankCode>" + bankcode +"</bankCode>" + 
                                            "<beneficiaryName>NA</beneficiaryName>" +
                                            "<narration>ACCOUNT TRANSFER " + description + "-" + tid + "-" + termRef + "</narration>" +
                                            "<amount>" + toCus + "</amount>" +
                                        "</bulkItem>" +
                                        "<bulkItem>" +
                                            //VAT
                                            "<uniqueId>" + transRef5 +"</uniqueId>" +
                                            "<accountId>" + vatAct +"</accountId>" +
                                            "<bankCode>" + vatActCode +"</bankCode>" + 
                                            "<beneficiaryName>NA</beneficiaryName>" +
                                            "<narration>VAT " + description + "-" + tid + "-" + termRef + "</narration>" +
                                            "<amount>" + vatKar + "</amount>" +
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
                                        var qry2 = "INSERT INTO frometranzact " + 
                                            "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                            "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                            "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, stampduty, vatkar, varetzn, etranzactresponse, etranzactecho, mainamount, fee, ref)" + 
                                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38)";
                                        pool.query(qry2, ["tms HOLDING", "tms HOLDING", "NA", transRef, tid, "NA", "CASH DEPOSIT / TRANSFER", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                            terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                            terminal.rows[0].accountname, rrn, "Debit Success", amount, agentamount, superagentfee, tmsfee, usemsc, terminal.rows[0].switchfee, destination, toCus, stamp, vatKar, vatEtzn, result.response.message, result.response, mainamount, fee, termRef], (err, resul) => {
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
                                                pool.query(qry3, [tid, "", vatKar, usemsc, rrn, stamp, terminal.rows[0].instantvaluepercentage,
                                                    terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                    terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                    terminal.rows[0].accountbank, "SETTLED", "vat" + tid, termRef], (err, resul) => {
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
                                                        pool.query(qry3, [tid, "", superagentfee, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                            terminal.rows[0].instantvaluetime, "CASH DEPOSIT / TRANSFER", 
                                                            terminal.rows[0].saaccountname, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountnumber,
                                                            terminal.rows[0].saaccountbank, "SETTLED", "superagent"+tid, termRef], (err, resul) => {
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
                                                                    terminal.rows[0].caaccountbank, "SETTLED", "tms" + tid, termRef], (err, resul) => {
                                                                    if (err) 
                                                                    {
                                                                        logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                        res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                    }else
                                                                    {
                                                                        //tms, SUPER AGENT, AGENT AND VAT
                                                                        var qry8 = "INSERT INTO agentsettlement " + 
                                                                            "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                        pool.query(qry8, [tid, tmsfee, terminal.rows[0].caaccountbank, 
                                                                            terminal.rows[0].caaccountcode, terminal.rows[0].caaccountname, 
                                                                            terminal.rows[0].caaccountnumber, description + " - " + result.response.reference, termRef], (err, resul) => {
                                                                            if (err) 
                                                                            {
                                                                                logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                return res.header("Content-Type",'Application/json').status(200).send(result.response);
                                                                            }else
                                                                            {
                                                                                var qry9 = "INSERT INTO agentsettlement " + 
                                                                                    "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                pool.query(qry9, [tid, superagentfee, terminal.rows[0].saaccountbank, 
                                                                                    terminal.rows[0].saaccountcode, terminal.rows[0].saaccountname, 
                                                                                    terminal.rows[0].saaccountnumber, description + " - " + result.response.reference, termRef], (err, resul) => {
                                                                                    if (err) 
                                                                                    {
                                                                                        logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                        logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                        return res.header("Content-Type",'Application/json').status(200).send(result.response);
                                                                                    }else
                                                                                    {
                                                                                        var qry10 = "INSERT INTO agentsettlement " + 
                                                                                            "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                        pool.query(qry10, [tid, toCus, "NA", 
                                                                                            bankcode, "NA", 
                                                                                            destination, description + " - " + result.response.reference, termRef], (err, resul) => {
                                                                                            if (err) 
                                                                                            {
                                                                                                logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                                logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                return res.header("Content-Type",'Application/json').status(200).send(result.response);
                                                                                            }else
                                                                                            {
                                                                                                var qry11 = "INSERT INTO agentsettlement " + 
                                                                                                    "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                                pool.query(qry11, [tid, vatKar, vatBank, 
                                                                                                    vatActCode, "tms VAT ACCOUNT", vatAct, description + " - " + result.response.reference, termRef], (err, resul) => {
                                                                                                    if (err) 
                                                                                                    {
                                                                                                        logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                                        logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                        return res.header("Content-Type",'Application/json').status(200).send(result.response);
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
                                            "bankname, bankcode, accountnumber, status, transactiontype, tmsfee, superagentfee, ref)" + 
                                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                        pool.query(qry3, [result.response.message, result.response.otherReference, result.response.error, 
                                            result.response, tid, amount, toCus, "NA", 
                                            bankcode, destination, "ERROR OCCURRED", "CASH DEPOSIT/TRANSFER", tmsfee, superagentfee, termRef], (err, resul) => {
                                            if (err) 
                                            {
                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                            }else
                                            {
                                                var mailOptions = {
                                                    from: emailHeading, // sender address
                                                    to: "commercial@tms.com, abigail.owobrenu@tms.com, anthony.akinajo@tms.com", // list of receivers
                                                    replyTo: replyTo,
                                                    subject: "ACCOUNT TRANSFER FAILURE", // Subject line
                                                    text: "ETRANZACT FAILED WITH \n" + JSON.stringify(result.response) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                };
                                                    
                                                transporter.sendMail(mailOptions, function(error, info){
                                                    if (error) {
                                                        return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                                    } else {
                                                        return res.header("Content-Type",'Application/json').status(500).send(result.response);
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
    var termRef = req.headers.rrn;

    logger.info(req.headers);

    logger.info("VTU PAYMENT");
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
                        var qry2 = "SELECT * FROM billsfee WHERE billername = $1";
                        pool.query(qry2, [provider], (err, bills) => {
                            if (err) 
                            {
                                logger.info("An error occurred");
                                logger.info(err);
                                return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
                            }else
                            {
                                var confee = bills.rows[0].conveniencefee;
                                var netamount = amount - parseFloat(confee);
                                var useper = ((parseFloat(bills.rows[0].percentagedue) / 100) * parseFloat(netamount)).toFixed(2);
                                if(bills.rows[0].percentagecapped !== "0.00")
                                {
                                    if(useper > parseFloat(bills.rows[0].percentagecapped))
                                        useper = parseFloat(bills.rows[0].percentagecapped);
                                }
                                logger.info("PERCENTAGE: " + useper);
                                
                                amount = amount - parseFloat(confee);// - parseFloat(useper);

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
                                                "<address>" + tid + "</address>" +
                                                "<destination>" + destination + "</destination>" +
                                                "<reference>" + rrn + termRef + "</reference>" +
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
                                console.log(xml);
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
                                        logger.info(response);
                                        if(response.statusCode === 200)
                                            console.log("IT IS 200")
                                        else
                                            console.log("IT IS NOT 200");

                                        if(response.statusCode === 200)
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
                                                        var tamount = amount - parseFloat(confee) - parseFloat(useper);
                                                        var tfee = parseFloat(confee) + parseFloat(useper);

                                                        var qry2 = "INSERT INTO frometranzact " + 
                                                            "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                                            "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                                            "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, vatkar, varetzn, etranzactresponse, etranzactecho, mainamount, fee, ref)" + 
                                                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37)";
                                                        pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "VTU", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                                            terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                            terminal.rows[0].accountname, transRef, "Transaction Success - CARD", amount, "0.00", "0.00", "0.00", "0.00", 
                                                            "0.00", destination + " - " + lineType + " - " + provider, "0.00", "0.00", "0.00", result.response.message, result.response, tamount, tfee, termRef], (err, resul) => {
                                                            if (err) 
                                                            {
                                                                logger.info(err);
                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                            }else
                                                            {
                                                                if(1)
                                                                {
                                                                    var cfee = bills.rows[0].conveniencefee;
                                                                    var netamount = amount - parseFloat(cfee);
                                                                    var agentconfee = parseFloat(cfee) - parseFloat(bills.rows[0].agentconveniencefee);
                                                                    var tmsconfee = parseFloat(cfee) - parseFloat(bills.rows[0].tmsconveniencefee);
                                                                    logger.info("AGENT CONVENIENCE DUE: " + agentconfee);
                                                                    logger.info("tms CONVENIENCE DUE: " + tmsconfee);
                                                                    var etranzactdue = parseFloat(cfee) - parseFloat(agentconfee) - parseFloat(tmsconfee);
                                                                    logger.info("ETRANZACT CONVENIENCE DUE: " + etranzactdue);
        
        
                                                                    var percentage = ((parseFloat(bills.rows[0].percentagedue) / 100) * parseFloat(netamount)).toFixed(2);
                                                                    if(bills.rows[0].percentagecapped !== "0.00")
                                                                    {
                                                                        if(percentage > parseFloat(bills.rows[0].percentagecapped))
                                                                            percentage = parseFloat(bills.rows[0].percentagecapped);
                                                                    }
                                                                    logger.info("PERCENTAGE: " + percentage);
        
                                                                    var tmspercentage = ((parseFloat(bills.rows[0].tmspercentage) / 100) * parseFloat(percentage)).toFixed(2);
                                                                    var agentpercentage = ((parseFloat(bills.rows[0].agentpercentage) / 100) * parseFloat(percentage)).toFixed(2);
                                                                    logger.info("tms PERCENTAGE: " + tmspercentage);
                                                                    logger.info("AGENT PERCENTAGE: " + agentpercentage);
                                                                    
                                                                    var creditAgent = parseFloat(agentconfee) + parseFloat(agentpercentage);
                                                                    var credittms = parseFloat(tmsconfee) + parseFloat(tmspercentage);
        
                                                                    logger.info("CREDIT AGENT: " + creditAgent);
                                                                    logger.info("CREDIT tms: " + credittms);
                                                                    //logger.info("VAT: " + vatKar);

                                                                    var qry3 = "INSERT INTO agencyinstant " + 
                                                                        "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                        "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                        ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                    pool.query(qry3, [tid, "", creditAgent, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                        terminal.rows[0].instantvaluetime, "BILLS PAYMENT", 
                                                                        terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                                        terminal.rows[0].accountbank, "SETTLED", "agent" + tid, termRef], (err, resul) => {
                                                                        if (err) 
                                                                        {
                                                                            logger.info("Error 1: " + err);
                                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                            res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                        }else
                                                                        {
                                                                            var qry3 = "INSERT INTO agencyinstant " + 
                                                                                "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                            pool.query(qry3, [tid, "", credittms, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                terminal.rows[0].instantvaluetime, "BILLS PAYMENT", 
                                                                                terminal.rows[0].caaccountname, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountnumber,
                                                                                terminal.rows[0].caaccountbank, "SETTLED", "tms" + tid, termRef], (err, resul) => {
                                                                                if (err) 
                                                                                {
                                                                                    logger.info("Error 1: " + err);
                                                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                }else
                                                                                {
                                                                                    if(1)
                                                                                    {
                                                                                        var totalBulk = parseFloat(creditAgent) + parseFloat(credittms);
                                                                                        var xml = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ws="http://ws.fundgate.etranzact.com/">
                                                                                            <soapenv:Header/>
                                                                                            <soapenv:Body>
                                                                                            <ws:process>
                                                                                                <request>
                                                                                                    <direction>request</direction>` +
                                                                                                    "<action>" + "BT" + "</action>" + 
                                                                                                    "<terminalId>" + tmsbulktid + "</terminalId>" +
                                                                                                    "<transaction>" +
                                                                                                        "<companyId>" + tmscompanyid + "</companyId>" +
                                                                                                        "<pin>" + tmsbulkpin + "</pin>" +
                                                                                                        "<amount>" + totalBulk + "</amount>" +
                                                                                                        "<reference>" + transRef3 + "</reference>" +
                                                                                                        "<endPoint>A</endPoint>" +
                                                                                                        "<senderName>" + "VTU - " + provider + destination + termRef + tid + "</senderName>" +
                                                                                                        "<token>N</token>" +
                                                                                                        "<bulkItems>" +
                                                                                                            "<bulkItem>" +
                                                                                                                //tms Share
                                                                                                                "<uniqueId>" + transRef1 +"</uniqueId>" +
                                                                                                                "<accountId>" + terminal.rows[0].caaccountnumber +"</accountId>" + 
                                                                                                                "<bankCode>" + terminal.rows[0].caaccountcode + "</bankCode>" + 
                                                                                                                "<beneficiaryName>" + terminal.rows[0].caaccountname + "</beneficiaryName>" +
                                                                                                                "<narration>" + "VTU - " + provider + destination + termRef + tid + "</narration>" +
                                                                                                                "<amount>" + credittms + "</amount>" +
                                                                                                            "</bulkItem>" +
                                                                                                            "<bulkItem>" +
                                                                                                                //Agent Share
                                                                                                                "<uniqueId>" + transRef2 +"</uniqueId>" +
                                                                                                                "<accountId>" + terminal.rows[0].accountnumber +"</accountId>" + 
                                                                                                                "<bankCode>" + terminal.rows[0].accountcode +"</bankCode>" + 
                                                                                                                "<beneficiaryName>" + terminal.rows[0].accountname + "</beneficiaryName>" +
                                                                                                                "<narration>" + "VTU - " + provider + destination + termRef + tid + "</narration>" +
                                                                                                                "<amount>" + creditAgent + "</amount>" +
                                                                                                            "</bulkItem>" +
                                                                                                        "</bulkItems>" +
                                                                                                    `</transaction>
                                                                                                </request>
                                                                                            </ws:process>
                                                                                            </soapenv:Body>
                                                                                        </soapenv:Envelope>`
                                                                                        console.log(xml);
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
                                                                                                parseString(fn, {explicitArray: false}, function (err, bulkresult) {
                                                                                                    if(err)
                                                                                                    {
                                                                                                        return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful 2x"});
                                                                                                    }else
                                                                                                    {
                                                                                                        if(bulkresult.response.error == '0')
                                                                                                        {
                                                                                                            var qry8 = "INSERT INTO agentsettlement " + 
                                                                                                                "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                                            pool.query(qry8, [tid, credittms, terminal.rows[0].caaccountbank, 
                                                                                                                terminal.rows[0].caaccountcode, terminal.rows[0].caaccountname, 
                                                                                                                terminal.rows[0].caaccountnumber, provider + " - " + bulkresult.response.reference, termRef], (err, resul) => {
                                                                                                                if (err) 
                                                                                                                {
                                                                                                                    logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                                                    logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                    return res.header("Content-Type",'Application/json').status(200).send(result.response);
                                                                                                                }else
                                                                                                                {
                                                                                                                    var qry9 = "INSERT INTO agentsettlement " + 
                                                                                                                        "(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
                                                                                                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                                                                                                                    pool.query(qry9, [tid, creditAgent, terminal.rows[0].saaccountbank, 
                                                                                                                        terminal.rows[0].saaccountcode, terminal.rows[0].saaccountname, 
                                                                                                                        terminal.rows[0].saaccountnumber, provider + " - " + bulkresult.response.reference, termRef], (err, resul) => {
                                                                                                                        if (err) 
                                                                                                                        {
                                                                                                                            logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
                                                                                                                            logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                            return res.header("Content-Type",'Application/json').status(200).send(result.response);
                                                                                                                        }else
                                                                                                                        {
                                                                                                                            logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                            return res.header("Content-Type",'Application/json').status(200).send(result.response);
                                                                                                                        }
                                                                                                                    });
                                                                                                                }
                                                                                                            });
                                                                                                        }else
                                                                                                        {                                                
                                                                                                            var qry3 = "INSERT INTO etranzactstatus " + 
                                                                                                                "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                                                                                                                "bankname, bankcode, accountnumber, status, transactiontype, tmsfee, superagentfee, ref)" + 
                                                                                                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                                                            pool.query(qry3, [result.response.message, result.response.otherReference, result.response.error, 
                                                                                                                result.response, tid, amount, amount, "NA", 
                                                                                                                provider, destination, "ERROR OCCURRED", "BILLSPAYMENT", credittms, "0.00", termRef], (err, resul) => {
                                                                                                                if (err) 
                                                                                                                {
                                                                                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                    return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                                                                                                }else
                                                                                                                {
                                                                                                                    logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                    return res.header("Content-Type",'Application/json').status(200).send(result.response);
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
                                                        });
                                                    }else
                                                    {    
                                                        amount = amount + parseFloat(confee);// + parseFloat(useper);
                                                        var qry3 = "INSERT INTO etranzactstatus " + 
                                                            "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                                                            "bankname, bankcode, accountnumber, status, transactiontype, ref)" + 
                                                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";
                                                        pool.query(qry3, [result.response.message, result.response.otherReference, result.response.error, 
                                                            result.response, tid, amount, amount, 
                                                            terminal.rows[0].accountbank, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                            "ERROR OCCURRED", lineType + "-" + provider + "-" + destination + "-VTU", termRef], (err, resul) => {
                                                            if (err) 
                                                            {
                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                                            }else
                                                            {
                                                                var mailOptions = {
                                                                    from: emailHeading, // sender address
                                                                    to: "commercial@tms.com, abigail.owobrenu@tms.com, anthony.akinajo@tms.com", // list of receivers
                                                                    replyTo: replyTo,
                                                                    subject: "VTU CARD FAILURE", // Subject line
                                                                    text: "ETRANZACT FAILED WITH \n" + JSON.stringify(result.response) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                };
                                                                    
                                                                transporter.sendMail(mailOptions, function(error, info){
                                                                    if (error) {
                                                                        return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                                                    } else {
                                                                        return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                                                    }
                                                                });
                                                            }
                                                        });
                                                    }
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

//BILLS PAYMENT - CARD
//OKAY
//Convenience fee is assumed to be 100.00
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
    var comingAmount = req.headers.amount.replace(/,/g, '');
    var amount = comingAmount;
    var termRef = req.headers.rrn;

    logger.info(req.headers);
    
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

                        var qry2 = "SELECT * FROM billsfee WHERE billername = $1";
                        pool.query(qry2, [lineType], (err, bills) => {
                            if (err) 
                            {
                                logger.info("An error occurred");
                                logger.info(err);
                                return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
                            }else
                            {
                                var confee = bills.rows[0].conveniencefee;
                                var netamount = amount - parseFloat(confee);
                                var useper = ((parseFloat(bills.rows[0].percentagedue) / 100) * parseFloat(netamount)).toFixed(2);
                                if(bills.rows[0].percentagecapped !== "0.00")
                                {
                                    if(useper > parseFloat(bills.rows[0].percentagecapped))
                                        useper = parseFloat(bills.rows[0].percentagecapped);
                                }
                                logger.info("PERCENTAGE: " + useper);
                                amount = amount - parseFloat(confee);// - parseFloat(useper);

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
                                                "<description>" + description + "-" + termRef + "-" + tid + "</description>" +
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
                                    //if(response)
                                    if(1)
                                    {
                                        logger.info(response.statusCode);
                                        logger.info("RESPONSE LOVE 2");
                                        //logger.info(response);
                                        if(response.statusCode === 200)
                                        {
                                            console.log("INSIDE 200 CODE");
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
                                                        var cfee = bills.rows[0].conveniencefee;
                                                        var etranzactdue = bills.rows[0].etranzactshare;
                                                        var netamount = parseFloat(comingAmount) - parseFloat(cfee);
                                                        var agentconfee = parseFloat(cfee) - parseFloat(etranzactdue) - parseFloat(bills.rows[0].tmsconveniencefee);
                                                        var tmsconfee = parseFloat(cfee) - parseFloat(etranzactdue) - parseFloat(bills.rows[0].agentconveniencefee);
                                                        
                                                        var vatKar = ((parseFloat(vat) / 100) * parseFloat(tmsconfee)).toFixed(2);
                                                        var vatEtzn = ((parseFloat(vat) / 100) * parseFloat(etranzactdue)).toFixed(2);
                                                        
                                                        var percentage = ((parseFloat(bills.rows[0].percentagedue) / 100) * parseFloat(netamount)).toFixed(2);
                                                        if(bills.rows[0].percentagecapped !== "0.00")
                                                        {
                                                            if(percentage > parseFloat(bills.rows[0].percentagecapped))
                                                                percentage = parseFloat(bills.rows[0].percentagecapped);
                                                        }
                                                        logger.info("PERCENTAGE: " + percentage);

                                                        var tmspercentage = ((parseFloat(bills.rows[0].tmspercentage) / 100) * parseFloat(percentage)).toFixed(2);
                                                        var agentpercentage = ((parseFloat(bills.rows[0].agentpercentage) / 100) * parseFloat(percentage)).toFixed(2);
                                                        logger.info("tms PERCENTAGE: " + tmspercentage);
                                                        logger.info("AGENT PERCENTAGE: " + agentpercentage);
                                                        
                                                        var creditAgent = parseFloat(agentconfee) + parseFloat(agentpercentage);
                                                        var credittms = parseFloat(tmsconfee) + parseFloat(tmspercentage);
                                                        
                                                        var tamount = comingAmount - parseFloat(confee) - parseFloat(useper);
                                                        var tfee = parseFloat(confee) + parseFloat(useper);

                                                        var qry2 = "INSERT INTO frometranzact " + 
                                                            "(daccount, dbankcode, dnumber, transref, tid, dpan, transtype, caccounta, cbankcodea, cpana," +
                                                            "cnumbera, caccountb, cbankcodeb, cpanb, cnumberb, origtransref, caccountc, cbankcodec, cpanc," +
                                                            "cnumberc, others, status, amount, agentamount, superagentamount, tmsamount, msc, switchfee, destination, tocustomer, responsetxn, vatkar, varetzn, etranzactresponse, etranzactecho, mainamount, fee, ref)" + 
                                                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38)";
                                                        pool.query(qry2, ["AGENT ACCOUNT", "AGENT ACCOUNT", "NA", rrn, tid, "NA", "BILLSPAYMENT", terminal.rows[0].caaccountnumber, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountbank,
                                                            terminal.rows[0].caaccountname, terminal.rows[0].saaccountnumber, terminal.rows[0].saaccountcode, terminal.rows[0].saaccountbank, terminal.rows[0].saaccountname, rrn, terminal.rows[0].accountnumber, terminal.rows[0].accountcode, terminal.rows[0].accountbank,
                                                            terminal.rows[0].accountname, transRef, "Transaction Success - CARD", comingAmount, "0.00", "0.00", "0.00", "0.00", 
                                                            "0.00", destination + " - " + lineType, "0.00", result.response.message, vatKar, vatEtzn, result.response.message, result.response, tamount, tfee, termRef], (err, resul) => {
                                                            if (err) 
                                                            {
                                                                logger.info(err);
                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                            }else
                                                            {
                                                                if(1)
                                                                {
                                                                    logger.info("AGENT CONVENIENCE DUE: " + agentconfee);
                                                                    logger.info("tms CONVENIENCE DUE: " + tmsconfee);
                                                                    logger.info("ETRANZACT CONVENIENCE DUE: " + etranzactdue);

                                                                    logger.info("CREDIT AGENT: " + creditAgent);
                                                                    logger.info("CREDIT tms: " + credittms);
                                                                    logger.info("VAT: " + vatKar);

                                                                    var qry3 = "INSERT INTO agencyinstant " + 
                                                                        "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                        "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                        ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                    pool.query(qry3, [tid, "", creditAgent, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                        terminal.rows[0].instantvaluetime, "BILLS PAYMENT - " + lineType + destination, 
                                                                        terminal.rows[0].accountname, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                                        terminal.rows[0].accountbank, "SETTLED", "agent" + tid, termRef], (err, resul) => {
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
                                                                            pool.query(qry3, [tid, "", credittms, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                terminal.rows[0].instantvaluetime, "BILLS PAYMENT - " + lineType + destination, 
                                                                                terminal.rows[0].caaccountname, terminal.rows[0].caaccountcode, terminal.rows[0].caaccountnumber,
                                                                                terminal.rows[0].caaccountbank, "SETTLED", "tms" + tid, termRef], (err, resul) => {
                                                                                if (err) 
                                                                                {
                                                                                    logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                    res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                }else
                                                                                {
                                                                                    var qry4 = "INSERT INTO agencyinstant " + 
                                                                                        "(tid, mid, amount, msc, rrn, stampduty, instantvaluepercentage, instantvaluetime, " + 
                                                                                        "transtype, accountname, accountbankcode, accountnumber, bankname, status, usertype, ref" +
                                                                                        ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)";
                                                                                    pool.query(qry4, [tid, "", vatKar, "", rrn, "", terminal.rows[0].instantvaluepercentage,
                                                                                        terminal.rows[0].instantvaluetime, "BILLS PAYMENT - " + lineType + destination, 
                                                                                        "tms VAT ACCOUNT", vatActCode, vatAct,
                                                                                        vatBank, "SETTLED", "vat" + tid, termRef], (err, resul) => {
                                                                                        if (err) 
                                                                                        {
                                                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                            res.status(500).send({"status": 500, "message": "Internal Error. Retry Later."});
                                                                                        }else
                                                                                        {
                                                                                            if(1)
                                                                                            {
                                                                                                var totalBulk = (parseFloat(creditAgent) + parseFloat(credittms) + parseFloat(vatKar)).toFixed(2);
                                                                                                var xml = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ws="http://ws.fundgate.etranzact.com/">
                                                                                                    <soapenv:Header/>
                                                                                                    <soapenv:Body>
                                                                                                    <ws:process>
                                                                                                        <request>
                                                                                                            <direction>request</direction>` +
                                                                                                            "<action>" + "BT" + "</action>" + 
                                                                                                            "<terminalId>" + tmsbulktid + "</terminalId>" +
                                                                                                            "<transaction>" +
                                                                                                                "<companyId>" + tmscompanyid + "</companyId>" +
                                                                                                                "<pin>" + tmsbulkpin + "</pin>" +
                                                                                                                "<amount>" + totalBulk + "</amount>" +
                                                                                                                "<reference>" + transRef3 + "</reference>" +
                                                                                                                "<endPoint>A</endPoint>" +
                                                                                                                "<senderName>" + "BILLS PAYMENT - " + lineType + destination + termRef + tid + "</senderName>" +
                                                                                                                "<token>N</token>" +
                                                                                                                "<bulkItems>" +
                                                                                                                    "<bulkItem>" +
                                                                                                                        //tms Share
                                                                                                                        "<uniqueId>" + transRef1 +"</uniqueId>" +
                                                                                                                        "<accountId>" + terminal.rows[0].caaccountnumber +"</accountId>" + 
                                                                                                                        "<bankCode>" + terminal.rows[0].caaccountcode + "</bankCode>" + 
                                                                                                                        "<beneficiaryName>" + terminal.rows[0].caaccountname + "</beneficiaryName>" +
                                                                                                                        "<narration>" + "BILLS PAYMENT - " + lineType + destination + termRef + tid + "</narration>" +
                                                                                                                        "<amount>" + credittms + "</amount>" +
                                                                                                                    "</bulkItem>" +
                                                                                                                    "<bulkItem>" +
                                                                                                                        //Agent Share
                                                                                                                        "<uniqueId>" + transRef2 +"</uniqueId>" +
                                                                                                                        "<accountId>" + terminal.rows[0].accountnumber +"</accountId>" + 
                                                                                                                        "<bankCode>" + terminal.rows[0].accountcode +"</bankCode>" + 
                                                                                                                        "<beneficiaryName>" + terminal.rows[0].accountname + "</beneficiaryName>" +
                                                                                                                        "<narration>" + "BILLS PAYMENT - " + lineType + destination + termRef + tid + "</narration>" +
                                                                                                                        "<amount>" + creditAgent + "</amount>" +
                                                                                                                    "</bulkItem>" +
                                                                                                                    "<bulkItem>" +
                                                                                                                        //VAT
                                                                                                                        "<uniqueId>" + transRef5 +"</uniqueId>" +
                                                                                                                        "<accountId>" + vatAct +"</accountId>" +
                                                                                                                        "<bankCode>" + vatActCode +"</bankCode>" + 
                                                                                                                        "<beneficiaryName>NA</beneficiaryName>" +
                                                                                                                        "<narration>" + "VAT-BILLS PAYMENT - " + lineType + destination + termRef + tid + "</narration>" +
                                                                                                                        "<amount>" + vatKar + "</amount>" +
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
                                                                                                        parseString(fn, {explicitArray: false}, function (err, bulkresult) {
                                                                                                            if(err)
                                                                                                            {
                                                                                                                return res.header("Content-Type",'application/json').status(500).send({"status": 500, "message": "Transaction Not Successful 2x"});
                                                                                                            }else
                                                                                                            {
                                                                                                                logger.info(bulkresult.response);
                                                                                                                if(bulkresult.response.error === '0')
                                                                                                                {
                                                                                                                    var qry8 = "INSERT INTO agentsettlement " + 
																														"(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
																														"VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
																													pool.query(qry8, [tid, credittms, terminal.rows[0].caaccountbank, 
																														terminal.rows[0].caaccountcode, terminal.rows[0].caaccountname, 
																														terminal.rows[0].caaccountnumber, destination + " - " + bulkresult.response.reference, termRef], (err, resul) => {
																														if (err) 
																														{
																															logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
																															logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
																															return res.header("Content-Type",'Application/json').status(200).send(result.response);
																														}else
																														{
																															var qry9 = "INSERT INTO agentsettlement " + 
																																"(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
																																"VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
																															pool.query(qry9, [tid, creditAgent, terminal.rows[0].saaccountbank, 
																																terminal.rows[0].saaccountcode, terminal.rows[0].saaccountname, 
																																terminal.rows[0].saaccountnumber, destination + " - " + bulkresult.response.reference, termRef], (err, resul) => {
																																if (err) 
																																{
																																	logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
																																	logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
																																	return res.header("Content-Type",'Application/json').status(200).send(result.response);
																																}else
																																{
																																	var qry11 = "INSERT INTO agentsettlement " + 
																																		"(tid, amount, bankname, bankcode, accountname, accountnumber, reference, ref) " + 
																																		"VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
																																	pool.query(qry11, [tid, vatKar, vatBank, 
																																		vatActCode, "tms VAT ACCOUNT", vatAct, destination + " - " + bulkresult.response.reference, termRef], (err, resul) => {
																																		if (err) 
																																		{
																																			logger.info("AGENCY SUCCESSFUL TRANSACTION BUT ERROR OCCURRED 2x");
																																			logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
																																			return res.header("Content-Type",'Application/json').status(200).send(result.response);
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
                                                                                                                    var qry3 = "INSERT INTO etranzactstatus " + 
                                                                                                                        "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                                                                                                                        "bankname, bankcode, accountnumber, status, transactiontype, tmsfee, superagentfee, ref)" + 
                                                                                                                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";
                                                                                                                    pool.query(qry3, [result.response.message, result.response.otherReference, result.response.error, 
                                                                                                                        result.response, tid, amount, amount, "NA", 
                                                                                                                        lineType, destination, "ERROR OCCURRED", "BILLSPAYMENT", credittms, "0.00", termRef], (err, resul) => {
                                                                                                                        if (err) 
                                                                                                                        {
                                                                                                                            logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                                                                            return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                                                                                                        }else
                                                                                                                        {
																															logger.info("Successful Txn. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
																															return res.header("Content-Type",'Application/json').status(200).send(result.response);
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
                                                                    });
                                                                }
                                                            }
                                                        });
                                                    }else
                                                    {
                                                        var qry3 = "INSERT INTO etranzactstatus " + 
                                                            "(message, otherreference, errorcode, fullresponse, tid, fullamount, refundamount, " +
                                                            "bankname, bankcode, accountnumber, status, transactiontype, ref)" + 
                                                            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";
                                                        pool.query(qry3, [result.response.message, result.response.otherReference, result.response.error, 
                                                            result.response, tid, comingAmount, comingAmount, 
                                                            terminal.rows[0].accountbank, terminal.rows[0].accountcode, terminal.rows[0].accountnumber,
                                                            "ERROR OCCURRED", lineType + "-" + destination + "-BILLS PAYMENT", termRef], (err, resul) => {
                                                            if (err) 
                                                            {
                                                                logger.info("Database Issue. Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                                                return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                                            }else
                                                            {
                                                                var mailOptions = {
                                                                    from: emailHeading, // sender address
                                                                    to: "commercial@tms.com, abigail.owobrenu@tms.com, anthony.akinajo@tms.com", // list of receivers
                                                                    replyTo: replyTo,
                                                                    subject: "BILLS PAYMENT FAILURE", // Subject line
                                                                    text: "ETRANZACT FAILED WITH \n" + JSON.stringify(result.response) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                                };
                                                                    
                                                                transporter.sendMail(mailOptions, function(error, info){
                                                                    if (error) {
                                                                        return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                                                    } else {
                                                                        return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                                                    }
                                                                });
                                                            }
                                                        });
                                                    }
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

//Private api to transfer money
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
                                                var mailOptions = {
                                                    from: emailHeading, // sender address
                                                    to: "commercial@tms.com, abigail.owobrenu@tms.com, anthony.akinajo@tms.com", // list of receivers
                                                    replyTo: replyTo,
                                                    subject: "MANUAL FUNDS TRANSFER FAILURE", // Subject line
                                                    text: "ETRANZACT FAILED WITH \n" + JSON.stringify(result.response) + "\n\n\nThe Request was: \n" + xml, // plain text body with html format
                                                };
                                                    
                                                transporter.sendMail(mailOptions, function(error, info){
                                                    if (error) {
                                                        return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                                    } else {
                                                        return res.header("Content-Type",'Application/json').status(500).send(result.response);
                                                    }
                                                });
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