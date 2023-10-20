var router = express.Router();

router.get("/download/:brand/:model/:version", function(req, res)
{
    try
    {
        var brand = req.params.brand;
        var model = req.params.model;
        var version = req.params.version;
        logger.info("Application Download Request For: " + brand + ". Model: " + model + ". Version: " + version + ". Ip: " + req.clientIp);
        const txn =
            `SELECT * FROM terminalapplications q WHERE brand = $1 AND model = $2 AND version = $3`;
        pool.query(txn, [brand, model, version], (err,  upload) => {    
            if (err) 
            {
                logger.info("App download Database connection error: " + err + ". Time: " + new Date().toLocaleString());
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
        logger.error("Application Download from: " + req.clientIp + ". Error Occurred ");
        res.header("Content-Type",'application/json').status(500).send({});
    }
});

module.exports.router = router;