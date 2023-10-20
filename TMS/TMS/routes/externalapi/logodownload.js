var router = express.Router();

router.get("/download/:bankcode/:version/:isreceipt", function(req, res)
{
    try
    {
        var bankcode = req.params.bankcode;
        var version = req.params.version;
        var isreceipt = req.params.isreceipt;
        
        logger.info("Logo Download Request For: Bankcode " + bankcode 
            + ". Version: " + version + ". Isreceipt: " + isreceipt + ". Ip: " + req.clientIp);
        const txn = 
            `SELECT * FROM logos q WHERE bankcode = $1 AND version = $2 AND isreceipt = $3`;
        pool.query(txn, [bankcode, version, isreceipt], (err,  upload) => {    
            if (err) 
            {
                logger.info("Logo download Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                res.header("Content-Type",'application/json').status(500).send({});
            }
            else
            {
                var filename = upload.rows[0].download;
                var file = path.join(__dirname + '/../../public' + filename);
                res.download(file);
            }
        });
	}catch(e)
    {
        logger.error("Logo Download from: " + req.clientIp + ". Error Occurred ");
        res.header("Content-Type",'application/json').status(500).send({});
    }
});

module.exports.router = router;