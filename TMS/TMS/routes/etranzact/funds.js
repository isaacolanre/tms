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



const wsdlURL = "https://ebank2.gtbank.com/GapsFileUploader_pilot/FileUploader.asmx";
var tmsAmount = "20.00";




//DISABLED TAKE NOTE
//VALIDATION
router.get("/validationothers", function(req, res) 
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
router.get("/oldvalidationothers", function(req, res) 
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
                    return res.status(200).send(resp);
                    //return res.status(500).send(resp);
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


//KEYSTONE
/*
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
                                                "DEBIT", "WALLET TRANSFER TO " + destination + ". NAME: " + receivername + ". TransId: " + transRef4], (err, resul) => {
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
*/

module.exports.router = router;