var router = express.Router();

router.get("/download/:type", function(req, res)
{
    try
    {
        var cardtype = req.params.type;
        const txn =
            `SELECT * FROM cardschemekeys q WHERE keytype = $1`;
        pool.query(txn, [cardtype], (err, scheme) => {    
            if (err) 
            {
                logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                res.header("Content-Type",'application/json').status(500).send({});
            }
            else
            {
                if(scheme.rows[0] === null)
                {
                    return res.header("Content-Type",'application/json').status(200).send({});
                }
                var obj = new Object();
	            obj["timestamp"] = getDateTimeSpec();
                var sch = scheme.rows[0];
                for(var i = 0; i < sch.length; i++)
                {
                    obj["name" + i.toString()] = sch[i].name;
                    obj["partialmatch" + i.toString()] = sch[i].partialmatch;
                    obj["aid" + i.toString()] = sch[i].aid;
                    obj["expirydate" + i.toString()] = sch[i].expirydate;
                    obj["exponent" + i.toString()] = sch[i].exponent;
                    obj["modulus" + i.toString()] = sch[i].modulus;
                    obj["keyindex" + i.toString()] = sch[i].keyindex;
                    obj["exponent" + i.toString()] = sch[i].exponent;
                    obj["modulus" + i.toString()] = sch[i].modulus;
                    obj["length" + i.toString()] = sch[i].length;
                    obj["checksum" + i.toString()] = sch[i].checksum;
                    obj["updated" + i.toString()] = sch[i].updated;
                }
                obj.status = 200;
			    obj.message = "Success";
                res.header("Content-Type",'application/json').status(200).send(obj);
            }
        });
    }catch(e)
    {
        logger.error("keys Download from: " + req.clientIp + ". Error Occurred ");
        res.header("Content-Type",'application/json').status(500).send({});
    }
});

module.exports.router = router;