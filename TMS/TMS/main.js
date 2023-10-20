express = require("express");
path = require("path");
winston = require("winston");
bodyParser = require("body-parser");
xmlparser = require('express-xml-bodyparser');
cookieParser = require("cookie-parser");
requestIp = require('request-ip');
pg = require("pg");
cors = require("cors");
helmet = require("helmet");
crypto = require("crypto");
fileUpload = require("express-fileupload");
ejs = require('ejs');
fs = require('fs');
fileExtension = require('file-extension');
nodemailer = require("nodemailer");
smtpTransport = require('nodemailer-smtp-transport');
randomstring = require("randomstring");
cryptoRandomString = require('crypto-random-string');
ActiveDirectory = require('activedirectory');
basic = require('basic-authorization-header');
parseString = require('xml2js').parseString;
request = require('request').defaults({ rejectUnauthorized: false })
handlebars = require('handlebars');
exportFromJSON = require('export-from-json');
sha256 = require('sha256');
sha512 = require('js-sha512');
bcrypt = require('bcrypt');
bcryptsaltRounds = 10;
net = require('net');
cISO8583 = require('ciso8583');
tls = require('tls');

emailHeading = '"TMS" <noreply@tms.ng>';
replyTo = "sanusi.segun@etopng.com";
//Abcd1234!
transporter = nodemailer.createTransport({
    host: 'tms.ng',
    port: 465,
    secure: true, // use SSL
    auth: {
        user: 'noreply@tms.ng',
        pass: 'Horp@$$2021'
    },
    pool: true
});


var plain = 'oneofakind55*';
var hash = '$2y$10$iV.hOrvNBYnj36TCzGHt/OwO7QCms/qmLNnPQoQsMchlEI3jp66zO';
hash = hash.replace(/^\$2y(.+)$/i, '$2a$1');

bcrypt.compare(plain, hash, function(err, results) {
    console.log("RESULTS: " + results);
});

bcrypt.hash("unical11", bcryptsaltRounds, function(err, hash) {
    console.log(hash);
});

var algorithm = "aes-256-ctr";
passworddb = "9japointcomngarshuaeromsleke1234094899hjfhjahdjhejrkkuÂ£$";
passwordtoken = "*(*9hjfhjahdjhejrkkuÂ£$%^unifiedpaymentservicelimitedikehjd)IKDJuzozi";

app = express();
app.use(cors());
app.use(helmet());
app.use(fileUpload());
app.use(xmlparser({
    explicitArray: false,
    normalize: false,
    normalizeTags: false,
    trim: true
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser("*wisdo(*(*(Dh%$Â£14*(*^$Â£$Â£mesadthatilove%$Â£$Â£$Â£-_"));

logger = winston.createLogger({
    transports: [
        new (winston.transports.Console)(),
        new (winston.transports.File)({
            name: 'info-file',
            filename: 'logs/info/filelog-info.log',
            maxsize:'10000000', 
            maxFiles:'10', 
            timestamp:true, 
            colorize: true,
            level: 'info'
        }),
        new (winston.transports.File)({
            name: 'error-file',
            filename: 'logs/error/filelog-error.log',
            maxsize:'10000000', 
            maxFiles:'10', 
            timestamp:true, 
            colorize: true,
            level: 'error'
        }),
        new (winston.transports.File)({
            name: 'debug-file',
            filename: 'logs/debug/filelog-debug.log',
            maxsize:'10000000', 
            maxFiles:'10', 
            timestamp:true, 
            colorize: true,
            level: 'debug'
        })
    ]
});


app.use(requestIp.mw());
app.use("/", express.static(path.join(__dirname, "public")));
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

lovegetdatetime = function()
{
    var str = "";
    var currentTime = new Date();
    var year = currentTime.getFullYear();
    var mnt = currentTime.getMonth() + 1;
    var day = currentTime.getDate();
    var hours = currentTime.getHours();
    var minutes = currentTime.getMinutes();
    var seconds = currentTime.getSeconds();
    if(mnt < 10)
    {
        mnt = "0" + mnt;
    }
    if(day < 10)
    {
        day = "0" + day
    }
    if (minutes < 10) {
        minutes = "0" + minutes;
    }
    if (seconds < 10) {
        seconds = "0" + seconds;
    }
    if (hours < 10) {
        hours = "0" + hours;
    }
    str = year.toString() + mnt.toString() + day.toString() + hours.toString() + minutes.toString() + seconds.toString();
    return str;
}

datetime = function()
{
    var str = "";
    var currentTime = new Date();
    var year = currentTime.getFullYear();
    var mnt = currentTime.getMonth() + 1;
    var day = currentTime.getDate();
    var hours = currentTime.getHours();
    var minutes = currentTime.getMinutes();
    var seconds = currentTime.getSeconds();
    if(mnt < 10)
    {
        mnt = "0" + mnt;
    }
    if(day < 10)
    {
        day = "0" + day
    }
    if (minutes < 10) {
        minutes = "0" + minutes;
    }
    if (seconds < 10) {
        seconds = "0" + seconds;
    }
    str += year + ":" + mnt + ":" + day + " " + hours + ":" + minutes + ":" + seconds + " ";
    if(hours > 11){
        str += "PM";
    } else {
        str += "AM";
    }
    return str;
}

compareDate = function(sessionDecrypted, fromDatabase)
    {
        if (sessionDecrypted === fromDatabase)
            return true;
        else
            return false;
    }

getDateTimeSpec = function()
    {
        var str = "";
        var currentTime = new Date();
        var year = currentTime.getFullYear();
        var mnt = currentTime.getMonth() + 1;
        var day = currentTime.getDate();
        var hours = currentTime.getHours();
        var minutes = currentTime.getMinutes();
        var seconds = currentTime.getSeconds();
        if(mnt < 10)
        {
            mnt = "0" + mnt;
        }
        if(day < 10)
        {
            day = "0" + day
        }
        if (hours < 10) {
            hours = "0" + hours;
        }
        if (minutes < 10) {
            minutes = "0" + minutes;
        }
        if (seconds < 10) {
            seconds = "0" + seconds;
        }
        str += year + "-" + mnt + "-" + day + " " + hours + ":" + minutes + ":" + seconds;
        return str;
    }

    
getDateTime = function()
    {
        var str = "";
        var currentTime = new Date();
        var year = currentTime.getFullYear();
        var mnt = currentTime.getMonth() + 1;
        var day = currentTime.getDate();
        var hours = currentTime.getHours();
        var minutes = currentTime.getMinutes();
        var seconds = currentTime.getSeconds();
        if(mnt < 10)
        {
            mnt = "0" + mnt;
        }
        if(day < 10)
        {
            day = "0" + day
        }
        if (minutes < 10) {
            minutes = "0" + minutes;
        }
        if (seconds < 10) {
            seconds = "0" + seconds;
        }
        str += year + ":" + mnt + ":" + day + ":" + hours + ":" + minutes + ":" + seconds + " ";
        if(hours > 11){
            str += "PM";
        } else {
            str += "AM";
        }
        return str;
    }

processorTime = function()
    {
        var str = "";
        var currentTime = new Date();
        var year = currentTime.getFullYear();
        var mnt = currentTime.getMonth() + 1;
        var day = currentTime.getDate();
        var hours = currentTime.getHours();
        var minutes = currentTime.getMinutes();
        var seconds = currentTime.getSeconds();
        if(mnt < 10)
        {
            mnt = "0" + mnt;
        }
        if(day < 10)
        {
            day = "0" + day
        }
        str += year + "/" + mnt + "/" + day;
        return str;
    }

encryptData = function(text, password) 
    { 
        try
        {
            var cipher = crypto.createCipher(algorithm, password)
            var crypted = cipher.update(text,'utf8','hex')
            crypted += cipher.final('hex');
            return crypted;
        }catch(e)
        {
            console.log("Cipher encryption Error");
            return null;
        }
    }

formatDateMessage = function(date) 
    {
        var year = date.getFullYear().toString();
        var month = (date.getMonth() + 101).toString().substring(1);
        var day = (date.getDate() + 100).toString().substring(1);
        return year + "-" + month + "-" + day;
    }

dateformatDateMessage = function(date, num) 
    {
        date.setDate(date.getDate() - num);
        var year = date.getFullYear().toString();
        var month = (date.getMonth() + 101).toString().substring(1);
        var day = (date.getDate() + 100).toString().substring(1);
        return year + "-" + month + "-" + day;
    }

decryptData = function(text, password) 
    { 
        try
        {
            var decipher = crypto.createDecipher(algorithm, password)
            var dec = decipher.update(text,'hex','utf8')
            dec += decipher.final('utf8');
            return dec;
        }catch(e)
        {
            console.log("Cipher decryption Error");
            return null;
        }
    }

pool = new pg.Pool({
    user: "postgres",
    host: "102.140.99.37",
    database: "etoptms",
    password: "etop!123456",
    port: 5432
});

pool.query("SELECT NOW();", (err, res) => {
    if (err) 
    {
        logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
    }
    else
    {
        logger.info("Server is now connected to postgresql database.... Time: " + new Date().toLocaleString());
    }
    //pool.end();
});

//Check for favicon
function ignoreFavicon(req, res, next) {
    if (req.originalUrl === '/favicon.ico') {
      res.status(204).json({nope: true});
    } else {
      next();
    }
}


app.use(ignoreFavicon);

app.get("/", function(req, res)
{
    try
    {
        res.clearCookie('token_tcm');
        res.clearCookie('username');
        logger.info("Spitting out website to: " + req.clientIp + ". Time: " + new Date().toLocaleString());
        res.status(200).render("login/userlogin", {});
    }catch(e)
    {
        logger.info("Home could not be served to " + req.clientIp);
        res.status(500).send("We are currently maintaining this application. We will be back online soon");
    };
});

var manager = require("./routes/manager.js");
app.use("/tms/", manager);


function sendMailDowntime(tids, appr, decl, nores)
{
    var lnk = path.join(__dirname + '/public/email/downtime/index.html');
    console.log("File Directory: " + lnk);
    fs.readFile(lnk, {encoding: 'utf-8'}, function (err, html) {
        if (err) {
          console.log(err);
        } else {
            var template = handlebars.compile(html);
            var replacements = {
                headingwise: "THERE IS A DOWNTIME",
                tids: tids,
                appr: appr,
                decl: decl,
                nores: nores
            };
            var htmlToSend = template(replacements);
            var mailOptions = {
                from: emailHeading, // sender address
                replyTo: replyTo,
                to: "sanusi.segun@etopng.com", // list of receivers
                subject: "TMS HIGH DECLINE RATE", // Subject line
                html: htmlToSend, //plain text body with html format
                attachments: [
                    {
                        filename: 'bg_1.jpg',
                        path: path.join(__dirname + '/public/email/downtime/images/bg_1.jpg'),
                        cid: 'bg_1.jpg'
                    },
                    {
                        filename: 'megaphone.png',
                        path: path.join(__dirname + '/public/email/downtime/images/megaphone.png'),
                        cid: 'megaphone.png'
                    },
                    {
                        filename: 'work.png',
                        path: path.join(__dirname + '/public/email/downtime/images/work.png'),
                        cid: 'work.png'
                    },
                    {
                        filename: 'network.png',
                        path: path.join(__dirname + '/public/email/downtime/images/network.png'),
                        cid: 'network.png'
                    },
                    {
                        filename: 'ticket.png',
                        path: path.join(__dirname + '/public/email/downtime/images/ticket.png'),
                        cid: 'ticket.png'
                    }
                ]
            };
            transporter.sendMail(mailOptions, function(error, info){
                if (error) {
                    console.log("ERROR OCCURRED");
                    console.log(error);
                } else {
                    console.log('Email sent: ' + info.response);
                }
            });
        }
    });
}

function sendMailNoProfit(tids, appr, decl, nores)
{
    var lnk = path.join(__dirname + '/public/email/downtime/decline.html');
    console.log("File Directory: " + lnk);
    fs.readFile(lnk, {encoding: 'utf-8'}, function (err, html) {
        if (err) {
          console.log(err);
        } else {
            var template = handlebars.compile(html);
            var replacements = {
                headingwise: "WE ARE NOT MAKING PROFIT",
                tids: tids,
                appr: appr,
                decl: decl,
                nores: nores
            };
            var htmlToSend = template(replacements);
            var mailOptions = {
                from: emailHeading, // sender address
                replyTo: replyTo,
                to: "sanusi.segun@etopng.com", // list of receivers
                subject: "TMS HIGH DECLINE RATE", // Subject line
                html: htmlToSend, //plain text body with html format
                attachments: [
                    {
                        filename: 'bg_1.jpg',
                        path: path.join(__dirname + '/public/email/downtime/images/bg_1.jpg'),
                        cid: 'bg_1.jpg'
                    },
                    {
                        filename: 'megaphone.png',
                        path: path.join(__dirname + '/public/email/downtime/images/megaphone.png'),
                        cid: 'megaphone.png'
                    },
                    {
                        filename: 'work.png',
                        path: path.join(__dirname + '/public/email/downtime/images/work.png'),
                        cid: 'work.png'
                    },
                    {
                        filename: 'network.png',
                        path: path.join(__dirname + '/public/email/downtime/images/network.png'),
                        cid: 'network.png'
                    },
                    {
                        filename: 'ticket.png',
                        path: path.join(__dirname + '/public/email/downtime/images/ticket.png'),
                        cid: 'ticket.png'
                    }
                ]
            };
            transporter.sendMail(mailOptions, function(error, info){
                if (error) {
                    console.log("ERROR OCCURRED");
                    console.log(error);
                } else {
                    console.log('Email sent: ' + info.response);
                }
            });
        }
    });
}

function sendMailOkay(tids, appr, decl, nores)
{
    var lnk = path.join(__dirname + '/public/email/downtime/normal.html');
    console.log("File Directory: " + lnk);
    fs.readFile(lnk, {encoding: 'utf-8'}, function (err, html) {
        if (err) {
          console.log(err);
        } else {
            var template = handlebars.compile(html);
            var replacements = {
                headingwise: "NORMAL APPROVAL RATE",
                tids: tids,
                appr: appr,
                decl: decl,
                nores: nores
            };
            var htmlToSend = template(replacements);
            var mailOptions = {
                from: emailHeading, // sender address
                replyTo: replyTo,
                to: "sanusi.segun@etopng.com", // list of receivers
                subject: "TMS NORMAL APPROVAL RATE", // Subject line
                html: htmlToSend, //plain text body with html format
                attachments: [
                    {
                        filename: 'bg_1.jpg',
                        path: path.join(__dirname + '/public/email/downtime/images/bg_1.jpg'),
                        cid: 'bg_1.jpg'
                    },
                    {
                        filename: 'megaphone.png',
                        path: path.join(__dirname + '/public/email/downtime/images/megaphone.png'),
                        cid: 'megaphone.png'
                    },
                    {
                        filename: 'work.png',
                        path: path.join(__dirname + '/public/email/downtime/images/work.png'),
                        cid: 'work.png'
                    },
                    {
                        filename: 'network.png',
                        path: path.join(__dirname + '/public/email/downtime/images/network.png'),
                        cid: 'network.png'
                    },
                    {
                        filename: 'ticket.png',
                        path: path.join(__dirname + '/public/email/downtime/images/ticket.png'),
                        cid: 'ticket.png'
                    }
                ]
            };
            transporter.sendMail(mailOptions, function(error, info){
                if (error) {
                    console.log("ERROR OCCURRED");
                    console.log(error);
                } else {
                    console.log('Email sent: ' + info.response);
                }
            });
        }
    });
}

uLastId = 0;
function downTimeMail() 
{
    var appr = 0;
    var dcln = 0;
    var crit = 0;
    var tids = "";
    if(uLastId === 0)
    {
        var txn = "SELECT * FROM ejournal WHERE current_date_uzoezi = $1 ORDER BY id ASC";
        pool.query(txn, [formatDateMessage(new Date())], (err, records) => {
            if (err) 
            {
                return;
            }
            else
            {
                logger.info("TOTAL TRANSACTION TO BE ANALYSED: " + records.rows.length);
                if(records.rows.length < 1)
                    return;
                for(var i = 0; i < records.rows.length; i++)
                {
                    var lastId = records.rows[i].id;
                    if(lastId > uLastId)
                        uLastId = lastId;
                    if(records.rows[i].response_code === "00")
                        appr = appr + 1;
                    else if(records.rows[i].response_code === null
                        || records.rows[i].response_code === "86"
                        || records.rows[i].response_code === "87"
                        || records.rows[i].response_code === "88"
                        || records.rows[i].response_code === "89")
                    {
                        crit = crit + 1;
                        tids = tids + ", " + records.rows[i].terminal_id;
                    }else
                        dcln = dcln + 1;
                }
                var tt = records.rows.length;
                var pappr = (appr / tt) * 100;
                var pdcln = (dcln / tt) * 100;
                var pcrit = (crit / tt) * 100;
                logger.info("% APPROVED: " + pappr);	
                logger.info("% DECLINED: " + pdcln);	
                logger.info("% ERROR: " + pcrit);
                
                if(pcrit > 10)
                {
                    sendMailDowntime(tids, pappr.toFixed(2), pdcln.toFixed(2), pcrit.toFixed(2));
                }else if(pdcln > 20)
                {
                    sendMailNoProfit(tids, pappr.toFixed(2), pdcln.toFixed(2), pcrit.toFixed(2));
                }else
                {
                    sendMailOkay(tids, pappr.toFixed(2), pdcln.toFixed(2), pcrit.toFixed(2));
                }
            }
        });
    }else
    {
        var txn = "SELECT * FROM ejournal WHERE id > $1 ORDER BY id ASC";
        pool.query(txn, [uLastId], (err, records) => {   
            if (err) 
            {
                return;
            }
            else
            {
                logger.info("TOTAL TRANSACTION TO BE ANALYSED: " + records.rows.length);
                if(records.rows.length < 1)
                    return;
                for(var i = 0; i < records.rows.length; i++)
                {
                    var lastId = records.rows[i].id;
                    if(lastId > uLastId)
                        uLastId = lastId;
                    if(records.rows[i].response_code === "00")
                        appr = appr + 1;
                    else if(records.rows[i].response_code === null
                        || records.rows[i].response_code === "86"
                        || records.rows[i].response_code === "87"
                        || records.rows[i].response_code === "88"
                        || records.rows[i].response_code === "89")
                    {
                        crit = crit + 1;
                        tids = tids + ", " + records.rows[i].terminal_id;
                    }else
                        dcln = dcln + 1;
                }
                var tt = records.rows.length;
                var pappr = (appr / tt) * 100;
                var pdcln = (dcln / tt) * 100;
                var pcrit = (crit / tt) * 100;
                logger.info("% APPROVED: " + pappr);	
                logger.info("% DECLINED: " + pdcln);	
                logger.info("% ERROR: " + pcrit);	

                if(pcrit > 10)
                {
                    sendMailDowntime(tids, pappr.toFixed(2), pdcln.toFixed(2), pcrit.toFixed(2));
                }else if(pdcln > 20)
                {
                    sendMailNoProfit(tids, pappr.toFixed(2), pdcln.toFixed(2), pcrit.toFixed(2));
                }else
                {
                    sendMailOkay(tids, pappr.toFixed(2), pdcln.toFixed(2), pcrit.toFixed(2));
                }
            }
        });
    }  
}
setInterval(downTimeMail, 30*60*1000);//Every 30 Minutes check for downtime


function setResponseCode(code)
{
	if(code == null)
	    return "No Response";
	if(code == "00")
    {
        return "Approved..";
    }else if(code == "01")
    {
        return "Refer to card issuer, special condition";
    }else if(code == "02")
    {
        return "Refer to card issuer";
    }else if(code == "03")
    {
        return "Invalid merchant";
    }else if(code == "04")
    {
        return "Pick-up card";
    }else if(code == "05")
    {
        return "Do not honor";
    }else if(code == "06")
    {
        return "Error";
    }else if(code == "07")
    {
        return "Pick-up card, special condition";
    }else if(code == "08")
    {
        return "Honor with identification";
    }else if(code == "09")
    {
        return "Request in progress";
    }else if(code == "10")
    {
        return "Approved, partial";
    }else if(code == "11")
    {
        return "Approved, VIP";
    }else if(code == "12")
    {
        return "Invalid transaction";
    }else if(code == "13")
    {
        return "Invalid amount";
    }else if(code == "14")
    {
        return "Invalid card number";
    }else if(code == "15")
    {
        return "No such issuer";
    }else if(code == "16")
    {
        return "Approved, update track 3";
    }else if(code == "17")
    {
        return "Customer cancellation";
    }else if(code == "18")
    {
        return "Customer dispute";
    }else if(code == "19")
    {
        return "Re-enter transaction";
    }else if(code == "20")
    {
        return "Invalid response";
    }else if(code == "21")
    {
        return "No action taken";
    }else if(code == "22")
    {
        return "Suspected malfunction";
    }else if(code == "23")
    {
        return "Unacceptable transaction fee";
    }else if(code == "24")
    {
        return "File update not supported";
    }else if(code == "25")
    {
        return "Unable to locate record";
    }else if(code == "26")
    {
        return "Duplicate record";
    }else if(code == "27")
    {
        return "File update field edit error";
    }else if(code == "28")
    {
        return "File update file locked";
    }else if(code == "29")
    {
        return "File update failed";
    }else if(code == "30")
    {
        return "Format error";
    }else if(code == "31")
    {
        return "Bank not supported";
    }else if(code == "32")
    {
        return "Completed partially";
    }else if(code == "33")
    {
        return "Expired card, pick-up";
    }else if(code == "34")
    {
        return "Suspected fraud, pick-up";
    }else if(code == "35")
    {
        return "Contact acquirer, pick-up";
    }else if(code == "36")
    {
        return "Restricted card, pick-up";
    }else if(code == "37")
    {
        return "Call acquirer security, pick-up";
    }else if(code == "38")
    {
        return "PIN tries exceeded, pick-up";
    }else if(code == "39")
    {
        return "No credit account";
    }else if(code == "40")
    {
        return "Function not supported";
    }else if(code == "41")
    {
        return "Lost card, pick-up";
    }else if(code == "42")
    {
        return "No universal account";
    }else if(code == "43")
    {
        return "Stolen card, pick-up";
    }else if(code == "44")
    {
        return "No investment account";
    }else if(code == "45")
    {
        return "Account closed";
    }else if(code == "46")
    {
        return "Identification required";
    }else if(code == "47")
    {
        return "Identification cross-check required";
    }else if(code == "48")
    {
        return "Error";
    }else if(code == "49")
    {
        return "Error";
    }else if(code == "50")
    {
        return "Error";
    }else if(code == "51")
    {
        return "Insufficient funds";
    }else if(code == "52")
    {
        return "No check account";
    }else if(code == "53")
    {
        return "No savings account";
    }else if(code == "54")
    {
        return "Expired card";
    }else if(code == "55")
    {
        return "Incorrect PIN";
    }else if(code == "56")
    {
        return "No card record";
    }else if(code == "57")
    {
        return "Transaction not permitted to cardholder";
    }else if(code == "58")
    {
        return "Transaction not permitted on terminal";
    }else if(code == "59")
    {
        return "Suspected fraud";
    }else if(code == "60")
    {
        return "Contact acquirer";
    }else if(code == "61")
    {
        return "Exceeds withdrawal limit";
    }else if(code == "62")
    {
        return "Restricted card";
    }else if(code == "63")
    {
        return "Security violation";
    }else if(code == "64")
    {
        return "Original amount incorrect";
    }else if(code == "65")
    {
        return "Exceeds withdrawal frequency";
    }else if(code == "66")
    {
        return "Call acquirer security";
    }else if(code == "67")
    {
        return "Hard capture";
    }else if(code == "68")
    {
        return "Response received too late";
    }else if(code == "69")
    {
        return "Advice received too late";
    }else if(code == "70")
    {
        return "Error";
    }else if(code == "71")
    {
        return "Error";
    }else if(code == "72")
    {
        return "Error";
    }else if(code == "73")
    {
        return "Error";
    }else if(code == "74")
    {
        return "Error";
    }else if(code == "75")
    {
        return "PIN tries exceeded";
    }else if(code == "76")
    {
        return "Error";
    }else if(code == "77")
    {
        return "Intervene, bank approval required";
    }else if(code == "78")
    {
        return "Intervene, bank approval required for partial amount";
    }else if(code == "79")
    {
        return "Error";
    }else if(code == "80")
    {
        return "Error";
    }else if(code == "81")
    {
        return "Error";
    }else if(code == "82")
    {
        return "Error";
    }else if(code == "83")
    {
        return "Error";
    }else if(code == "84")
    {
        return "Error";
    }else if(code == "85")
    {
        return "Error";
    }
    
    
    else if(code == "86")
    {
        return "Could Not Connect";
    }else if(code == "87")
    {
        return "Could Not Connect";
    }else if(code == "88")
    {
        return "No Response From Nibss";
    }else if(code == "89")
    {
        return "No Response From Nibss";
    }
    
    else if(code == "90")
    {
        return "Cut-off in progress";
    }else if(code == "91")
    {
        return "Issuer or switch inoperative";
    }else if(code == "92")
    {
        return "Routing error";
    }else if(code == "93")
    {
        return "Violation of law";
    }else if(code == "94")
    {
        return "Duplicate transaction";
    }else if(code == "95")
    {
        return "Reconcile error";
    }else if(code == "96")
    {
        return "System malfunction";
    }else if(code == "97")
    {
        return "Reserved for future Postilion use";
    }else if(code == "98")
    {
        return "Exceeds cash limit";
    }else if(code == "99")
    {
        return "Error";
    }else
    {
        return "Response Unknown";
    }
}

function formatDt(date) {
    return date.toString().slice(0, 24);
}

function emailAllAgentsMerchants() 
{
    var currentTime = new Date();
    var firstTime = new Date();
    firstTime.setHours(4,0,0); // 4am
    var t1 = currentTime.getTime() - firstTime.getTime();
    var dif = t1 / 1000;
    //if(dif < -1 || dif > 500)
    if(dif < -1 || dif > 500)
    {  
        logger.info("Time not matched....");
        return;
    }

    var qry = "SELECT * FROM terminalconfiguration";
    console.log("QURYING TIDS");
    pool.query(qry, (err, result) => { 
        if (err) 
        {
            logger.info("Database connection error: " + err + ". Time: " +  new Date().toLocaleString());
            return;
        }
        else
        {
            //logger.info("NUMBER OF TERMINALS: " + result.rows.length);
            if(result.rows.length < 1)
            {
                logger.info("No Terminal Available. Time: " +  new Date().toLocaleString());
                return;
            }else
            {
                result.rows.forEach(function(transaction ) {
                    logger.info("NAME: " + transaction.merchantname);
                    logger.info("ADDRESS: " + transaction.merchantaddress);
                    var txn = "SELECT * FROM ejournal WHERE terminal_id = $1 AND current_date_uzoezi = $2 ORDER BY id ASC";
                    pool.query(txn, [transaction.tid, dateformatDateMessage(new Date(), 1)], (err, ejorn) => {
                        if (err) 
                        {
                            logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                            return;
                        }
                        else
                        {
                            var arr = [];
                            var appr = 0;
                            var dcln = 0;
                            var crit = 0;
                            var pappr = 0;
                            var pdcln = 0;
                            var pcrit = 0;
                            var active = "";
                            var tab = `<table>
                                            <tr>
                                                <th>MASKED PAN</th>
                                                <th>AMOUNT</th>
                                                <th>AUTH CODE</th>
                                                <th>RESP CODE</th>
                                                <th>RRN</th>
                                                <th>STAN</th>
                                                <th>TIME STAMP</th>
                                            </tr>`;
                            var dat = "";                
                            if(ejorn.rows.length < 1)
                            {
                                pappr = 0;
                                pdcln = 0;
                                pcrit = 0;
                                active = "TERMINAL IS NOT ACTIVE";
                                return;
                            }else
                            {
                                for(var i = 0; i < ejorn.rows.length; i++)
                                {
                                    if(ejorn.rows[i].response_code === "00")
                                        appr = appr + 1;
                                    else if(ejorn.rows[i].response_code === null
                                        || ejorn.rows[i].response_code === "86"
                                        || ejorn.rows[i].response_code === "87"
                                        || ejorn.rows[i].response_code === "88"
                                        || ejorn.rows[i].response_code === "89")
                                    {
                                        crit = crit + 1;
                                    }else
                                        dcln = dcln + 1;

                                    dat = dat + "<tr><td>" + ejorn.rows[i].masked_pan + "</td>" + 
                                        "<td>" + ejorn.rows[i].amount + "</td>" + 
                                        "<td>" + ejorn.rows[i].auth_code + "</td>" + 
                                        "<td>" + setResponseCode(ejorn.rows[i].response_code) + "</td>" + 
                                        "<td>" + ejorn.rows[i].rrn + "</td>" + 
                                        "<td>" + ejorn.rows[i].stan + "</td>" + 
                                        "<td>" + formatDt(ejorn.rows[i].current_timestamp) + "</td></tr>";

                                    var obj = new Object();
                                    obj.maskedpan = ejorn.rows[i].masked_pan;
                                    obj.amount = ejorn.rows[i].amount;
                                    obj.authcode = ejorn.rows[i].auth_code;
                                    obj.resp = setResponseCode(ejorn.rows[i].response_code);
                                    obj.rrn = ejorn.rows[i].rrn;
                                    obj.stan = ejorn.rows[i].stan;
                                    obj.timestamp = formatDt(ejorn.rows[i].current_timestamp);
                                    arr.push(obj);
                                }
                                var tt = ejorn.rows.length;
                                var pappr = (appr / tt) * 100;
                                var pdcln = (dcln / tt) * 100;
                                var pcrit = (crit / tt) * 100;
                                active = "TERMINAL IS TRANSACTING";

                                logger.info("% APPROVED: " + pappr.toFixed(2));	
                                logger.info("% DECLINED: " + pdcln.toFixed(2));	
                                logger.info("% ERROR: " + pcrit.toFixed(2));
                                tab = tab + dat + `</table>`;
                                var lnk = path.join(__dirname + '/public/email/downtime/transactions.html');
                                fs.readFile(lnk, {encoding: 'utf-8'}, function (err, html) {
                                    if (err) {
                                        console.log(err);
                                    } else {
                                        const data = arr;
                                        const fileName = 'transactions'
                                        const exportType = 'xls'
                                        const result = exportFromJSON({
                                            data,
                                            fileName,
                                            exportType,
                                            processor (content, type, fileName) {
                                                return content
                                            }
                                        });
                                        var filen = randomstring.generate({
                                                        length: 12,
                                                        charset: 'alphabetic'
                                                    });
                                        filen = filen + ".xls";
                                        var file = path.join(__dirname + '/public/downloads/' + filen);
                                        fs.writeFile(file, result, function (err) {
                                            if (err)
                                            {
                                                logger.info("Error occurred while creating xls");
                                                logger.info(err);
                                                return;
                                            }else
                                            {
                                                var template = handlebars.compile(html);
                                                var replacements = {
                                                    headingwise: "TRANSACTION RECORDS FOR " + transaction.tid + " " + dateformatDateMessage(new Date(), 1),
                                                    appr: pappr.toFixed(2),
                                                    decl: pdcln.toFixed(2),
                                                    nores: pcrit.toFixed(2),
                                                    name: transaction.merchantname,
                                                    address: transaction.merchantaddress,
                                                    active: active,
                                                    tab: tab
                                                };
                                                var htmlToSend = template(replacements);
                                                var mailOptions = {
                                                    from: emailHeading, // sender address
                                                    replyTo: replyTo,
                                                    to: transaction.email, // list of receivers
                                                    subject: "TMS RECORDS " + transaction.tid + " " + dateformatDateMessage(new Date(), 1), // Subject line
                                                    html: htmlToSend, //plain text body with html format
                                                    attachments: [
                                                        {
                                                            filename: filen,
                                                            path: file
                                                        },
                                                        {
                                                            filename: 'bg_1.jpg',
                                                            path: path.join(__dirname + '/public/email/downtime/images/bg_1.jpg'),
                                                            cid: 'bg_1.jpg'
                                                        },
                                                        {
                                                            filename: 'megaphone.png',
                                                            path: path.join(__dirname + '/public/email/downtime/images/megaphone.png'),
                                                            cid: 'megaphone.png'
                                                        },
                                                        {
                                                            filename: 'work.png',
                                                            path: path.join(__dirname + '/public/email/downtime/images/work.png'),
                                                            cid: 'work.png'
                                                        },
                                                        {
                                                            filename: 'network.png',
                                                            path: path.join(__dirname + '/public/email/downtime/images/network.png'),
                                                            cid: 'network.png'
                                                        },
                                                        {
                                                            filename: 'ticket.png',
                                                            path: path.join(__dirname + '/public/email/downtime/images/ticket.png'),
                                                            cid: 'ticket.png'
                                                        }
                                                    ]
                                                };
                                                transporter.sendMail(mailOptions, function(error, info){
                                                    if (error) {
                                                        console.log("ERROR OCCURRED");
                                                        console.log(error);
                                                    } else {
                                                        console.log('Email sent: ' + info.response);
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
            }
        }
    });
}
setInterval(emailAllAgentsMerchants, 5*60*1000);//Every Day

function emailIdleTerminals() 
{
    var currentTime = new Date();
    var firstTime = new Date();
    firstTime.setHours(5,0,0); // 5am
    var t1 = currentTime.getTime() - firstTime.getTime();
    var dif = t1 / 1000;
    if(dif < -1 || dif > 500)
    {  
        logger.info("Time not matched....");
        return;
    }
    var qry = "SELECT * FROM terminalconfiguration";
    pool.query(qry, (err, result) => { 
        if (err) 
        {
            logger.info("Database connection error: " + err + ". Time: " +  new Date().toLocaleString());
            return;
        }
        else
        {
            //logger.info("NUMBER OF TERMINALS: " + result.rows.length);
            if(result.rows.length < 1)
            {
                logger.info("No Terminal Available. Time: " +  new Date().toLocaleString());
                return;
            }else
            {
                var arr = [];
                var tot = result.rows.length;
                var chk = 0;
                var per = 0;
                var tab = `<table>
                                <tr>
                                    <th>TID</th>
                                    <th>MERCHANT NAME</th>
                                    <th>MERCHANT ADDRESS</th>
                                    <th>BANK</th>
                                    <th>DAYS</th>
                                    <th>TMO</th>
                                    <th>LAST TXN</th>
                                </tr>`;
                var dat = ""; 
                result.rows.forEach(function(transaction) {
                    var txn = "SELECT * FROM ejournal WHERE terminal_id = $1 ORDER BY id DESC LIMIT 1";
                    pool.query(txn, [transaction.tid], (err, ejorn) => {
                        if (err) 
                        {
                            logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                            return;
                        }
                        else
                        {
                            chk = chk + 1;
                            logger.info("CHECKER: " + chk);
                            logger.info("TOTAL: " + tot);
                            if(1)
                            {
                                var ldate = "";
                                if(ejorn.rows.length < 1)
                                    ldate = "2020-04-02";
                                else
                                    ldate = ejorn.rows[0].current_date_uzoezi;
                                var cdate = formatDateMessage(new Date());
                                const date1 = new Date(ldate);
                                const date2 = new Date(cdate);
                                const diffTime = Math.abs(date2 - date1);
                                const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)); 
                                if(diffDays > 2)
                                {
                                    per = per + 1;
                                    var b = "";
                                    if(ejorn.rows.length < 1)
                                        b = "NA";
                                    else
                                        b = formatDt(ejorn.rows[0].current_timestamp);
                                    dat = dat + "<tr><td>" + transaction.tid + "</td>" + 
                                            "<td>" + transaction.merchantname + "</td>" + 
                                            "<td>" + transaction.merchantaddress + "</td>" + 
                                            "<td>" + transaction.bankname + "</td>" + 
                                            "<td>" + diffDays + "</td>" +
                                            "<td>" + transaction.tmo + "</td>" + 
                                            "<td>" + b + "</td></tr>";
                                    var obj = new Object();
                                    obj.tid = transaction.tid;
                                    obj.merchantname = transaction.merchantname;
                                    obj.merchantaddress = transaction.merchantaddress;
                                    obj.bank = transaction.bankname;
                                    obj.days = diffDays - 1;
                                    obj.tmo = transaction.tmo;
                                    obj.lasttxn = b;
                                    arr.push(obj);
                                }
                                if(chk === tot)
                                {
                                    logger.info("INSIDE THE MAIN GUY");
                                    tab = tab + dat + `</table>`;
                                    var pwk = (per / tot) * 100;
                                    var lnk = path.join(__dirname + '/public/email/downtime/inactive.html');
                                    fs.readFile(lnk, {encoding: 'utf-8'}, function (err, html) {
                                        if (err) {
                                            console.log(err);
                                        } else {
                                            const data = arr;
                                            const fileName = 'inactiveterminals'
                                            const exportType = 'xls'
                                            const result = exportFromJSON({
                                                data,
                                                fileName,
                                                exportType,
                                                processor (content, type, fileName) {
                                                    return content
                                                }
                                            });
                                            var filen = randomstring.generate({
                                                            length: 12,
                                                            charset: 'alphabetic'
                                                        });
                                            filen = filen + ".xls";
                                            var file = path.join(__dirname + '/public/downloads/' + filen);
                                            fs.writeFile(file, result, function (err) {
                                                if (err)
                                                {
                                                    logger.info("Error occurred while creating xls");
                                                    logger.info(err);
                                                    return;
                                                }else
                                                {
                                                    var template = handlebars.compile(html);
                                                    var replacements = {
                                                        headingwise: "INACTIVE TERMINALS " + formatDateMessage(new Date()),
                                                        tab: tab,
                                                        tot: tot,
                                                        per: per,
                                                        pwk: pwk.toFixed(2)
                                                    };
                                                    var htmlToSend = template(replacements);
                                                    var mailOptions = {
                                                        from: emailHeading, // sender address
                                                        replyTo: replyTo,
                                                        to: "sanusi.segun@etopng.com", // list of receivers
                                                        subject: "TMS INACTIVE TERMINALS " + formatDateMessage(new Date()), // Subject line
                                                        html: htmlToSend, //plain text body with html format
                                                        attachments: [
                                                            {
                                                                filename: filen,
                                                                path: file
                                                            },
                                                            {
                                                                filename: 'bg_1.jpg',
                                                                path: path.join(__dirname + '/public/email/downtime/images/bg_1.jpg'),
                                                                cid: 'bg_1.jpg'
                                                            },
                                                            {
                                                                filename: 'megaphone.png',
                                                                path: path.join(__dirname + '/public/email/downtime/images/megaphone.png'),
                                                                cid: 'megaphone.png'
                                                            },
                                                            {
                                                                filename: 'work.png',
                                                                path: path.join(__dirname + '/public/email/downtime/images/work.png'),
                                                                cid: 'work.png'
                                                            },
                                                            {
                                                                filename: 'network.png',
                                                                path: path.join(__dirname + '/public/email/downtime/images/network.png'),
                                                                cid: 'network.png'
                                                            },
                                                            {
                                                                filename: 'ticket.png',
                                                                path: path.join(__dirname + '/public/email/downtime/images/ticket.png'),
                                                                cid: 'ticket.png'
                                                            }
                                                        ]
                                                    };
                                                    transporter.sendMail(mailOptions, function(error, info){
                                                        if (error) {
                                                            console.log("ERROR OCCURRED");
                                                            console.log(error);
                                                            return;
                                                        } else {
                                                            console.log('Email sent: ' + info.response);
                                                            return;
                                                        }
                                                    });
                                                }
                                            });
                                        }
                                    });
                                }else
                                    return;
                            }
                        }
                    });
                });
            }
        }
    });
}
setInterval(emailIdleTerminals, 5*60*1000);//Every Day


function cleanUpDirectory()
{
    console.log("INSIDE CLEANING UP");
    var directory = path.join(__dirname + '/public/downloads/');                                
    fs.readdir(directory, (err, files) => {
        if (err)
        {
            console.log("CLEANING UP ERROR: " + err);
        }else
        {
            for (const file of files) {
                fs.unlink(path.join(directory, file), err => {
                    if (err) throw err;
                });
            }
        }
    });
}
setInterval(cleanUpDirectory, 30*60*1000);//Every 30 Minutes




app.post("/send/reports", function(req, res)
{
    var txn = "SELECT * FROM walletactivies WHERE username = $1 AND tousedate BETWEEN $2 AND $3";
    pool.query(txn, [req.body.username, req.body.sd, req.body.ed], (err, result) => {
        if (err) 
        {
            logger.info("Database connection error: " + err + ". Time: " +  new Date().toLocaleString());
            return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
        }
        else
        {
            if(result.rows.length < 1)
            {
                logger.info("No Outstanding Available. Time: " +  new Date().toLocaleString());
                return res.status(200).send({"status": 200, "message": "No Data."});
            }else
            {
                var len = result.rows.length;
                var inc = 0;
                var dat = "";
                var arr = [];
                var tab = `<table>
                                            <tr>
                                                <th>AMOUNT</th>
                                                <th>OLD AMOUNT</th>
                                                <th>NEW AMOUNT</th>
                                                <th>TRANS MODE</th>
                                                <th>INFO</th>
                                                <th>DATE</th>
                                                <th>STATUS</th>
                                                <th>TIME</th>
                                            </tr>`;
                result.rows.forEach(function(quries ) {
                    dat = dat + "<tr><td>" + quries.amount + "</td>" + 
                        "<td>" + quries.oldamount + "</td>" + 
                        "<td>" + quries.newamount + "</td>" + 
                        "<td>" + quries.transmode + "</td>" +  
                        "<td>" + quries.transinfo + "</td>" + 
                        "<td>" + quries.tousedate + "</td>" + 
                        "<td>" + quries.status + "</td>" + 
                        "<td>" + formatDt(quries.timestamp) + "</td></tr>";

                    var obj = new Object();
                    obj.amount = quries.amount;
                    obj.oldamount = quries.oldamount;
                    obj.newamount = quries.newamount;
                    obj.transmode = quries.transmode;
                    obj.transinfo = quries.transinfo;
                    obj.tousedate = quries.tousedate;
                    obj.status = quries.status;
                    obj.timestamp = formatDt(quries.timestamp);
                    arr.push(obj);
                    
                    inc = inc + 1;
                    if(inc === len)
                    {
                        tab = tab + dat + `</table>`;
                        var lnk = path.join(__dirname + '/public/email/downtime/cowry.html');
                        fs.readFile(lnk, {encoding: 'utf-8'}, function (err, html) {
                            if (err) {
                                console.log(err);
                            } else {
                                const data = arr;
                                const fileName = 'cowry'
                                const exportType = 'xls'
                                const result = exportFromJSON({
                                    data,
                                    fileName,
                                    exportType,
                                    processor (content, type, fileName) {
                                        return content
                                    }
                                });
                                var filen = randomstring.generate({
                                                length: 12,
                                                charset: 'alphabetic'
                                            });
                                filen = filen + ".xls";
                                var file = path.join(__dirname + '/public/downloads/' + filen);
                                fs.writeFile(file, result, function (err) {
                                    if (err)
                                    {
                                        logger.info("Error occurred while creating xls");
                                        logger.info(err);
                                        return res.status(500).send({"status": 500, "message": "ERROR OCCURRED."});
                                    }else
                                    {
                                        res.status(200).send({"status": 200, "message": "SENT."});
                                        var usedTime = req.body.sd + " TO " + req.body.ed;
                                        var template = handlebars.compile(html);
                                        var replacements = {
                                            headingwise: "ACCOUNT TRANSACTIONS FOR " + usedTime ,
                                            usetime: usedTime,
                                            usedate: dateformatDateMessage(new Date(), 0),
                                            tab: tab
                                        };
                                        var htmlToSend = template(replacements);
                                        var mailOptions = {
                                            from: emailHeading, // sender address
                                            replyTo: replyTo,
                                            to: req.body.username, // list of receivers
                                            subject: "ACCOUNT TRANSACTIONS FOR " + usedTime, // Subject line
                                            html: htmlToSend, //plain text body with html format
                                            attachments: [
                                                {
                                                    filename: filen,
                                                    path: file
                                                },
                                                {
                                                    filename: 'bg_1.jpg',
                                                    path: path.join(__dirname + '/public/email/downtime/images/bg_1.jpg'),
                                                    cid: 'bg_1.jpg'
                                                },
                                                {
                                                    filename: 'megaphone.png',
                                                    path: path.join(__dirname + '/public/email/downtime/images/megaphone.png'),
                                                    cid: 'megaphone.png'
                                                },
                                                {
                                                    filename: 'work.png',
                                                    path: path.join(__dirname + '/public/email/downtime/images/work.png'),
                                                    cid: 'work.png'
                                                },
                                                {
                                                    filename: 'network.png',
                                                    path: path.join(__dirname + '/public/email/downtime/images/network.png'),
                                                    cid: 'network.png'
                                                },
                                                {
                                                    filename: 'ticket.png',
                                                    path: path.join(__dirname + '/public/email/downtime/images/ticket.png'),
                                                    cid: 'ticket.png'
                                                }
                                            ]
                                        };
                                        transporter.sendMail(mailOptions, function(error, info){
                                            if (error) {
                                                console.log("ERROR OCCURRED");
                                                console.log(error);
                                            } else {
                                                console.log('Email sent: ' + info.response);
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
});


app.all("*", function(req, res)
{
    logger.info("In Home route");
    logger.info(req.url);
    logger.info("Wrong URL. Redirecting to home. From: " + req.clientIp + ". Time: " + new Date().toLocaleString());
    res.redirect("/");
});

//80 for less traffic
app.listen(8088, function()
{
    logger.info("TMS on port 8088" + ". Time: " + new Date().toLocaleString());
});