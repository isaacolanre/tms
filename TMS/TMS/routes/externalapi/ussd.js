var router = express.Router();
var request = require('request').defaults({ rejectUnauthorized: false })



const { CoralPayCConnect, Utilities } = require('coralpay-c-connect-node-sdk');
const { join } = require('path');

const getRefCode = async (amount, tid, mid) => {
    const utilities = new Utilities({
        publicEncryptionKeyPath: join(__dirname, './keys/coralpay.public.key.txt'), // absolute path to public key for encrypting requests
        privateKeyPath: join(__dirname, './keys/private.txt'), // absolute path to your private key for decrypting responses
        passphrase: "unical11", // the passpharse for your private key (can be ignored)
        trace: true // enable this to see log of requests and responses or pass your custom logging function
    });

    var json = {"userInfo":{"userName": "intellifin","password": "1nt3LL171nb@678"},"posRequest":{"terminalId": tid,"amount": amount,"merchantId": mid,"transactionType": 0}};
    console.log(json);
    return await utilities.encryptRequest(json);
};

const getRefCodeCashout = async (amount, tid, mid) => {
    const utilities = new Utilities({
        publicEncryptionKeyPath: join(__dirname, './keys/coralpay.public.key.txt'), // absolute path to public key for encrypting requests
        privateKeyPath: join(__dirname, './keys/private.txt'), // absolute path to your private key for decrypting responses
        passphrase: "unical11", // the passpharse for your private key (can be ignored)
        trace: true // enable this to see log of requests and responses or pass your custom logging function
    });

    var json = {"userInfo":{"userName": "intellifin","password": "1nt3LL171nb@678"},"posRequest":{"terminalId": tid,"amount": amount,"merchantId": mid,"transactionType": 30}};
    console.log(json);
    return await utilities.encryptRequest(json);
};

const decrypt = async (response, tid, mid) => {
    console.log(response);
    const coral = new CoralPayCConnect({
        cConnectServiceBaseUrl: 'https://cgrhs.coralpay.com:9443/', 
        cConnectPublicEncryptionKeyPath: join(__dirname, './keys/coralpay.public.key.txt'), 
        privateKeyPath: join(__dirname, './keys/private.txt'),
        passphrase: 'unical11',
        userName: 'intellifin',
        password: '1nt3LL171nb@678',
        merchantId: mid,
        terminalId: tid,
        trace: true
    });
    return await coral.decryptResponse(response);
};

router.get("/tms/first/:amount", function(req, res) 
{
    logger.info(req.params.amount);
    req.params.amount = req.params.amount.replace(/,/g, '');
    logger.info("First Request");
    logger.info(req.params.amount);
    logger.info(new Date().toLocaleString());
    try {
        getRefCode(parseFloat(req.params.amount), req.headers.tid.toString(), req.headers.mid.toString()).then((payload) => {
            logger.info(payload);
            logger.info("SENDING TO CORALPAY");
            var clientServerOptions = {
                uri: 'https://cgrhs.coralpay.com:9443/coralpay-payment/api/ussd/ussdreference',
                body: payload,
                method: 'POST',
                headers: {
                    'Content-Type': 'text/plain'
                }
            }
            request(clientServerOptions, function (error, response) {
                if(error)
                {
                    logger.info("ERROR: " + error);
                    return;
                }
                if(response)
                {
                    logger.info("RESPONSE");
                    logger.info("First Response");
                    logger.info(new Date().toLocaleString());
                    logger.info(response.body);
                    decrypt(response.body, req.headers.tid.toString(), req.headers.mid.toString()).then((decrypted) => {
                        console.log("Waiting for decryption");
                        logger.info(decrypted);
                        console.log(decrypted);
                        return res.header("Content-Type",'text/plain').status(200).send(decrypted);
                    }).catch(e => 
                        logger.info(e));
                }
            });
        }).catch(e => 
            logger.info(e));
    } catch (e) {
        logger.info(e);
    }
});

router.get("/tms/cashout/:amount", function(req, res) 
{
    logger.info("Inside Cashout");
    logger.info(req.params.amount);
    req.params.amount = req.params.amount.replace(/,/g, '');
    logger.info(req.params.amount);
    logger.info(req.headers.tid);
    logger.info(req.headers.mid);

    try {
        getRefCodeCashout(parseFloat(req.params.amount), req.headers.tid.toString(), req.headers.mid.toString()).then((payload) => {
            logger.info(payload);
            logger.info("SENDING TO CORALPAY");
            var clientServerOptions = {
                uri: 'https://cgrhs.coralpay.com:9443/coralpay-payment/api/ussd/ussdreference',
                body: payload,
                method: 'POST',
                headers: {
                    'Content-Type': 'text/plain'
                }
            }
            request(clientServerOptions, function (error, response) {
                if(error)
                {
                    logger.info("ERROR: " + error);
                    return;
                }
                if(response)
                {
                    logger.info("RESPONSE");
                    logger.info(response.body);
                    decrypt(response.body, req.headers.tid.toString(), req.headers.mid.toString()).then((decrypted) => {
                        console.log("Waiting for decryption");
                        console.log(decrypted);
                        return res.header("Content-Type",'text/plain').status(200).send(decrypted);
                    }).catch(e => 
                        logger.info(e));
                }
            });
        }).catch(e => 
            logger.info(e));
    } catch (e) {
        logger.info(e);
    }
});

const confirmPayment = async (amount, refcode, tid, mid) => {
    const utilities = new Utilities({
        publicEncryptionKeyPath: join(__dirname, './keys/coralpay.public.key.txt'), // absolute path to public key for encrypting requests
        privateKeyPath: join(__dirname, './keys/private.txt'), // absolute path to your private key for decrypting responses
        passphrase: "unical11", // the passpharse for your private key (can be ignored)
        trace: true // enable this to see log of requests and responses or pass your custom logging function
    });
    var json = {"userInfo":{"userName": "intellifin","password": "1nt3LL171nb@678"},"posRequest":{"terminalId": tid,"amount": amount, "reference": refcode.toString(), "merchantId": mid}};
    console.log(json);
    return await utilities.encryptRequest(json);
};

router.get("/tms/second/:amount/:refcode", function(req, res) 
{
    logger.info(req.params.amount);
    req.params.amount = req.params.amount.replace(/,/g, '');
    logger.info(req.params.amount);
    logger.info("Get Status");
    logger.info(new Date().toLocaleString());
    try {
        confirmPayment(parseFloat(req.params.amount), req.params.refcode, req.headers.tid.toString(), req.headers.mid.toString()).then((payload) => {
            logger.info(payload);
            logger.info("SENDING TO CORALPAY FOR COMFIRMATION");
            var clientServerOptions = {
                uri: 'https://cgrhs.coralpay.com:9443/coralpay-payment/api/ussd/confirmposting',
                body: payload,
                method: 'POST',
                headers: {
                    'Content-Type': 'text/plain'
                }
            }
            request(clientServerOptions, function (error, response) {
                if(error)
                {
                    logger.info("ERROR: " + error);
                    return;
                }
                if(response)
                {
                    logger.info("Response");
                    logger.info(new Date().toLocaleString());
                    logger.info(response.body);
                    decrypt(response.body, req.headers.tid.toString(), req.headers.mid.toString()).then((decrypted) => {
                        console.log("Waiting for confirmation decryption");
                        logger.info(decrypted);
                        console.log(decrypted);
                        return res.header("Content-Type",'text/plain').status(200).send(decrypted);
                    }).catch(e => 
                        logger.info(e));
                }
            });
        }).catch(e => 
            logger.info(e));
    } catch (e) {
        logger.info(e);
    }
});


module.exports.router = router;