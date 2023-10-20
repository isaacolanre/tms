var router = express.Router();

router.get("/download", function(req, res)
{
    try
    {
        //Pending when they are ready
        //Reference retail download
        var banks = "United Bank for Africa - 033###" +
                "WEMA BANK - 035###" + 
                "Access Bank plc - 044###" +
                "Ecobank Nigeria - 050###" +
                "FirstBank - 011###" + 
                "Zenith Bank - 057###" + 
                "Guaranty Trust Bank - 058###" +
                "Polaris Bank - 076###" + 
                "Enterprise Bank - 084###" +
                "First City Monument Bank - 214###" + 
                "Unity Bank PLC - 215###" +
                "Sterling Bank - 232###" + 
                "Fidelity Bank - 070###" + 
                "Union Bank - 032###" + 
                "Keystone Bank - 082###" + 
                "Diamond Bank - 063###" +
                "STANBIC IBTC BANK - 039###" +
                "STANDARD CHARTERED - 068###" +
                "pocketmoni - 700###";
        return res.header("Content-Type",'text/plain').status(200).send(banks);
    }catch(e)
    {
        logger.error("Karrabo Retail Download from: " + req.clientIp + ". Error Occurred ");
        return res.header("Content-Type",'application/json').status(500).send({});
    }
});

module.exports.router = router;