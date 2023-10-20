var router = express.Router();

router.get("/download", function(req, res)
{
    try
    {
        var banks = "CENTRAL BANK OF NIGERIA - 001###" +
        "FIRST BANK OF NIGERIA PLC - 011###" +
        "NIGERIA INTERNATINAL BANK (CITIBANK) - 023###" +
        "HERITAGE BANK - 030###" +
        "UNION BANK OF NIGERIA PLC - 032###" +
        "UNITED BANK FOR AFRICA PLC - 033###" +
        "WEMA BANK PLC - 035###" +
        "ACCESS BANK NIGERIA LTD - 044###" +
        "ECOBANK NIGERIA PLC - 050###" +
        "ZENITH INTERNATIONAL BANK LTD - 057###" +
        "GUARANTY TRUST BANK PLC - 058###" +
        "FBNQuest Merchant Bank Limited - 060002###" +
        "DIAMOND BANK LTD - 063###" +
        "STANDARD CHARTERED BANK NIGERIA LTD - 068###" +
        "FIDELITY BANK PLC - 070###" +
        "SKYE BANK PLC - 076###" +
        "KEYSTONE BANK LTD - 082###" +
        "IBILE MFB - 090118###" +
        "HASAL MICROFINANCE BANK - 090121###" +
        "SUNTRUST BANK - 100###" +
        "PROVIDUS BANK - 101###" +
        "FIRST CITY MONUMENT BANK - 214###" +
        "UNITY BANK PLC - 215###" +
        "STANBIC IBTC BANK PLC - 221###" +
        "STERLING BANK PLC - 232###" +
        "JAIZ BANK PLC 301###" +
        "PAGA 327###" +
        "RAND MERCHANT BANK 502###" +
        "PARALLEX MFB 526###" +
        "NPF Microfinance Bank 552###" +
        "CORONATION MERCHANT BANK 559###" +
        "Page MFBank 560###" +
        "New Prudential Bank 561###" +
        "FSDH MERCHANT BANK LIMIT 601###" +
        "FINATRUST MICROFINANCE BANK 608###";
        return res.header("Content-Type",'text/plain').status(200).send(banks);
    }catch(e)
    {
        logger.error("Karrabo Retail Download from: " + req.clientIp + ". Error Occurred ");
        return res.header("Content-Type",'application/json').status(500).send({});
    }
});

router.get("/vendorbankcode", function(req, res)
{
    try
    {
        var banks = "CENTRAL BANK OF NIGERIA - 001080032###" + 
        "FIRST BANK OF NIGERIA PLC - 011151003###" +
        "NIGERIA INTERNATINAL BANK (CITIBANK) - 023150005###" +
        "HERITAGE BANK - 030150014###" + 
        "UNION BANK OF NIGERIA PLC - 032154568###" +
        "UNITED BANK FOR AFRICA PLC - 033152048###" + 
        "WEMA BANK PLC - 035150103###" +
        "ACCESS BANK NIGERIA LTD - 044150291###" + 
        "ECOBANK NIGERIA PLC - 050150010###" +
        "ZENITH INTERNATIONAL BANK LTD - 057150013###" + 
        "GUARANTY TRUST BANK PLC - 058152052###" +
        "FBNQuest Merchant Bank Limited - 060002600###" + 
        "DIAMOND BANK LTD - 063150162###" +
        "STANDARD CHARTERED BANK NIGERIA LTD - 068150015###" + 
        "FIDELITY BANK PLC - 070150003###" +
        "SKYE BANK PLC - 076151365###" +
        "KEYSTONE BANK LTD - 082150017###" +
        "IBILE MFB - 090185090###" + 
        "HASAL MICROFINANCE BANK - 090118509###" +
        "SUNTRUST BANK - 100152049###" + 
        "PROVIDUS BANK - 101152019###" +
        "FIRST CITY MONUMENT BANK - 214150018###" +
        "UNITY BANK PLC - 215082334###" +
        "STANBIC IBTC BANK PLC - 221159522###" + 
        "STERLING BANK PLC - 232150016###" +
        "JAIZ BANK PLC - 301080020###" +
        "PAGA - 327155327###" +
        "RAND MERCHANT BANK - 502155502###" +
        "PARALLEX MFB - 526155261###" +
        "NPF Microfinance Bank - 552155552###" +
        "CORONATION MERCHANT BANK - 559155591###" +
        "Page MFBank - 560155560###" +
        "New Prudential Bank - 561155561###" +
        "FSDH MERCHANT BANK LIMIT - 601155601###" +
        "FINATRUST MICROFINANCE BANK - 608155608###";
        return res.header("Content-Type",'text/plain').status(200).send(banks);
    }catch(e)
    {
        logger.error("Karrabo Retail Download from: " + req.clientIp + ". Error Occurred ");
        return res.header("Content-Type",'application/json').status(500).send({});
    }
});




module.exports.router = router;