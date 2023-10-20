var router = express.Router();

router.get("/billers", function(req, res)
{
    try
    {
        var str = new Date().toLocaleString();
        var token = req.cookies.token_tcm;
        var username = req.cookies.username;
        try
        {
            var qry = "SELECT * FROM tokens WHERE token = $1 AND username = $2";
            pool.query(qry, [token, username], (err, result) => { 
                if (err) 
                {
                    logger.info("Database connection error: " + err + ". Username: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                    return res.redirect("/");
                }
                else
                {
                    if(result.rows.length !== 1)
                    {
                        logger.info("Incorrect Token Details. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                        res.redirect("/");
                    }else
                    {
                        if(result.rows[0].role !== "user")
                        {
                            logger.info("Not authorized for. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                            return res.redirect("/tms/dashboard/show");
                        }
                        var response = result.rows[0];
                        var role = response.role;
                        var usertype = response.usertype;
                        logger.info("Spitting out all users to: " + req.clientIp + ". Time: " + new Date().toLocaleString());
                        return res.status(200).render("bills/billers", {details: JSON.stringify(response), role: role, usertype, usertype});
                    }
                }
            });
        }catch(e)
        {
            logger.info("Token Confirmation Error");
            return res.redirect("/");
        }
    }catch(e)
    {
        logger.info(req.cookies.username + " is not authorize to view URL 3");
        return res.redirect("/");
    }
});

router.get("/getalldata", function(req, res)
{
    try
    {
        var str = new Date().toLocaleString();
        var token = req.cookies.token_tcm;
        var username = req.cookies.username;
        try
        {
            var qry = "SELECT * FROM tokens WHERE token = $1 AND username = $2";
            pool.query(qry, [token, username], (err, result) => { 
                if (err) 
                {
                    logger.info("Database connection error: " + err + ". Username: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                    return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
                }
                else
                {
                    if(result.rows.length !== 1)
                    {
                        logger.info("Incorrect Token Details. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                        return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
                    }else
                    {
                        if(result.rows[0].role !== "user")
                        {
                            logger.info("Not authorized for. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                            return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Authorized."});
                        }
                        var qry2 = "SELECT * FROM billers";
                        pool.query(qry2, (err, resul) => {
                            if (err) 
                            {
                                logger.info("Database Issue. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                res.status(500).send({"status": 500, "message": "Cannot Signup. Retry Later."});
                            }else
                            {
                                return res.status(200).send({"status": 200, "message": JSON.stringify(resul.rows)});
                            }
                        });
                    }
                }
            });
        }catch(e)
        {
            logger.info("Token Confirmation Error");
            return res.status(500).send({"status": 500, "message": "An Error Occurred. Token Issue."});
        }
    }catch(e)
    {
        logger.info(req.cookies.username + " is not authorize to view URL 3");
        return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Authorized."});
    }
});

router.delete("/deletedata/:id", function(req, res)
{
    try
    {
        var id = req.params.id;
        var qry = "SELECT * FROM tokens WHERE token = $1 AND username = $2";
        pool.query(qry, [req.cookies.token_tcm, req.cookies.username], (err, result) => {
            if (err) 
            {
                logger.info("tms TOKEN CHECK FAILED FOR " + req.clientIp);
                return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
            }else
            {
                //if(result.rows.length !== 1)
                if(result.rows === undefined || result.rows.length !== 1)
                {
                    logger.info("Kindly login again " + req.clientIp);
                    return res.status(500).send({"status": 500, "message": "Token Issue"});
                }else if(result.rows[0].role !== "user")
                {
                    logger.info(req.headers.username + " not qualified to access endpoint. Client: " + req.clientIp);
                    return res.status(500).send({"status": 500, "message": "Not Qualified to Access Endpoint"});
                }else
                {
                    var date1 = new Date();
                    var date2 = new Date(result.rows[0].timestop);
                    var timeDiff = date1.getTime() - date2.getTime();
                    var dif = timeDiff / 1000;
                    if(dif >= 1)
                    {
                        logger.info("Time out. Please login again. " + req.clientIp);
                        return res.status(500).send({"status": 500, "message": "Time Out. Please Login."});
                    }else
                    {
                        var qry2 = "DELETE FROM billers where id = $1";
                        pool.query(qry2, [id], (err, resul) => {
                            if (err) 
                            {
                                logger.info("Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                res.status(500).send({"status": 500, "message": "Others depend on this."});
                            }else
                            {
                                return res.status(200).send({"status": 200, "message": "Successful Delete."});
                            }
                        });
                    }
                }
            }
        });
    }catch(e)
    {
        logger.info(e);
        logger.info("Having Issues with User Delete " + req.clientIp);
        res.status(500).send({"status": 500, "message": "Runtime error occurred. Try Later."});
    }
});

router.post("/show", function(req, res)
{
    try
    {
        var qry = "SELECT * FROM tokens WHERE token = $1 AND username = $2";
        pool.query(qry, [req.cookies.token_tcm, req.cookies.username], (err, result) => {
            if (err) 
            {
                logger.info("tms TOKEN CHECK FAILED FOR " + req.clientIp);
                return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
            }else
            {
                //if(result.rows.length !== 1)
                if(result.rows === undefined || result.rows.length !== 1)
                {
                    logger.info("Kindly login again " + req.clientIp);
                    return res.status(500).send({"status": 500, "message": "Token Issue"});
                }else if(result.rows[0].role !== "user")
                {
                    logger.info(req.headers.username + " not qualified to access endpoint. Client: " + req.clientIp);
                    return res.status(500).send({"status": 500, "message": "Not Qualified to Access Endpoint"});
                }else
                {
                    var date1 = new Date();
                    var date2 = new Date(result.rows[0].timestop);
                    var timeDiff = date1.getTime() - date2.getTime();
                    var dif = timeDiff / 1000;
                    if(dif >= 1)
                    {
                        logger.info("Time out. Please login again. " + req.clientIp);
                        return res.status(500).send({"status": 500, "message": "Time Out. Please Login."});
                    }else
                    {
                        var id = req.body.id;
                        var billername = req.body.billername;
                        var vendorid = req.body.vendorid;
                        var istoken = req.body.istoken.toLowerCase() == 'true' ? true : false;
                        var printall = req.body.printall.toLowerCase() == 'true' ? true : false;
                        var conveniencefee = req.body.conveniencefee;
                        var printvalidation = req.body.printvalidation.toLowerCase() == 'true' ? true : false;
                        var labels = req.body.labels;
                        var products = req.body.products;
                        var addedby = req.cookies.username;
                        var maker = req.cookies.username;
                        var namecreated = req.cookies.username;
                        var datecreated = datetime();
                        var datemodified = datetime();
                        //console.log(req.body)
                        
                        //console.log(req.body)
                        if(req.body.edit === 'true')
                        {
                            const query =
                            "UPDATE billers SET billername = $1, vendorid = $2, istoken = $3," + 
                                "printall = $4, conveniencefee = $5, printvalidation = $6, labels = $7, products = $8, addedby = $9, maker = $10, ifavailable = $11, checker = $12"
                                + ", namemodified = $13, datemodified = $14 WHERE id = $15";
                            pool.query(query, [billername, vendorid, istoken, printall, conveniencefee, 
                                printvalidation, labels, products, addedby, maker, "true", " ", namecreated, datemodified, id], (err,  results) => {    
                                if (err) 
                                {
                                    logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                                    res.status(500).send({"status": 500, "message": "An error occurred. Retry Later."});
                                }
                                else
                                {
                                    return res.status(200).send({"status": 200, "message": "Update Successful."});
                                }
                            });
                        }else
                        {
                            const query =
                            "INSERT INTO billers (billername, vendorid, istoken, printall, conveniencefee, " + 
                                " printvalidation, labels, products, addedby, maker, ifavailable, namecreated, datecreated) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";
                            pool.query(query, [billername, vendorid, istoken, printall, conveniencefee, printvalidation, labels, products, addedby, 
                                maker, "true", namecreated, datecreated], (err,  results) => {    
                                if (err) 
                                {
                                    logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                                    res.status(500).send({"status": 500, "message": "An error occurred. Retry Later."});
                                }
                                else
                                {
                                    return res.status(200).send({"status": 200, "message": "Successfully Added."});
                                }
                            });
                        }
                    }
                }
            }
        });
    }catch(e)
    {
        logger.info(e);
        logger.info("Having Issues with User Delete " + req.clientIp);
        res.status(500).send({"status": 500, "message": "Runtime error occurred. Try Later."});
    }
});

router.get("/menu", function(req, res)
{
    try
    {
        var str = new Date().toLocaleString();
        var token = req.cookies.token_tcm;
        var username = req.cookies.username;
        try
        {
            var qry = "SELECT * FROM tokens WHERE token = $1 AND username = $2";
            pool.query(qry, [token, username], (err, result) => { 
                if (err) 
                {
                    logger.info("Database connection error: " + err + ". Username: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                    return res.redirect("/");
                }
                else
                {
                    if(result.rows.length !== 1)
                    {
                        logger.info("Incorrect Token Details. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                        res.redirect("/");
                    }else
                    {
                        if(result.rows[0].role !== "user")
                        {
                            logger.info("Not authorized for. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                            return res.redirect("/tms/dashboard/show");
                        }
                        var response = result.rows[0];
                        var role = response.role;
                        var usertype = response.usertype;
                        logger.info("Spitting out all users to: " + req.clientIp + ". Time: " + new Date().toLocaleString());
                        return res.status(200).render("bills/billsmenu", {details: JSON.stringify(response), role: role, usertype, usertype});
                    }
                }
            });
        }catch(e)
        {
            logger.info("Token Confirmation Error");
            return res.redirect("/");
        }
    }catch(e)
    {
        logger.info(req.cookies.username + " is not authorize to view URL 3");
        return res.redirect("/");
    }
});

router.get("/menudata", function(req, res)
{
    try
    {
        var str = new Date().toLocaleString();
        var token = req.cookies.token_tcm;
        var username = req.cookies.username;
        try
        {
            var qry = "SELECT * FROM tokens WHERE token = $1 AND username = $2";
            pool.query(qry, [token, username], (err, result) => { 
                if (err) 
                {
                    logger.info("Database connection error: " + err + ". Username: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                    return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
                }
                else
                {
                    if(result.rows.length !== 1)
                    {
                        logger.info("Incorrect Token Details. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                        return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
                    }else
                    {
                        if(result.rows[0].role !== "user")
                        {
                            logger.info("Not authorized for. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                            return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Authorized."});
                        }
                        var qry2 = "SELECT * FROM billsmenu";
                        pool.query(qry2, (err, resul) => {
                            if (err) 
                            {
                                logger.info("Database Issue. User: " + username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                res.status(500).send({"status": 500, "message": "Cannot Signup. Retry Later."});
                            }else
                            {
                                return res.status(200).send({"status": 200, "message": JSON.stringify(resul.rows)});
                            }
                        });
                    }
                }
            });
        }catch(e)
        {
            logger.info("Token Confirmation Error");
            return res.status(500).send({"status": 500, "message": "An Error Occurred. Token Issue."});
        }
    }catch(e)
    {
        logger.info(req.cookies.username + " is not authorize to view URL 3");
        return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Authorized."});
    }
});

router.delete("/billsmenudata/:id", function(req, res)
{
    try
    {
        var id = req.params.id;
        var qry = "SELECT * FROM tokens WHERE token = $1 AND username = $2";
        pool.query(qry, [req.cookies.token_tcm, req.cookies.username], (err, result) => {
            if (err) 
            {
                logger.info("tms TOKEN CHECK FAILED FOR " + req.clientIp);
                return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
            }else
            {
                //if(result.rows.length !== 1)
                if(result.rows === undefined || result.rows.length !== 1)
                {
                    logger.info("Kindly login again " + req.clientIp);
                    return res.status(500).send({"status": 500, "message": "Token Issue"});
                }else if(result.rows[0].role !== "user")
                {
                    logger.info(req.headers.username + " not qualified to access endpoint. Client: " + req.clientIp);
                    return res.status(500).send({"status": 500, "message": "Not Qualified to Access Endpoint"});
                }else
                {
                    var date1 = new Date();
                    var date2 = new Date(result.rows[0].timestop);
                    var timeDiff = date1.getTime() - date2.getTime();
                    var dif = timeDiff / 1000;
                    if(dif >= 1)
                    {
                        logger.info("Time out. Please login again. " + req.clientIp);
                        return res.status(500).send({"status": 500, "message": "Time Out. Please Login."});
                    }else
                    {
                        var qry2 = "DELETE FROM billsmenu where id = $1";
                        pool.query(qry2, [id], (err, resul) => {
                            if (err) 
                            {
                                logger.info("Database Issue. User: " + req.cookies.username + ". Ip: " + req.clientIp + ". Time: " +  new Date().toLocaleString());
                                res.status(500).send({"status": 500, "message": "Others depend on this."});
                            }else
                            {
                                return res.status(200).send({"status": 200, "message": "Successful Delete."});
                            }
                        });
                    }
                }
            }
        });
    }catch(e)
    {
        logger.info(e);
        logger.info("Having Issues with User Delete " + req.clientIp);
        res.status(500).send({"status": 500, "message": "Runtime error occurred. Try Later."});
    }
});

router.post("/senddata", function(req, res)
{
    try
    {
        var qry = "SELECT * FROM tokens WHERE token = $1 AND username = $2";
        pool.query(qry, [req.cookies.token_tcm, req.cookies.username], (err, result) => {
            if (err) 
            {
                logger.info("tms TOKEN CHECK FAILED FOR " + req.clientIp);
                return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
            }else
            {
                //if(result.rows.length !== 1)
                if(result.rows === undefined || result.rows.length !== 1)
                {
                    logger.info("Kindly login again " + req.clientIp);
                    return res.status(500).send({"status": 500, "message": "Token Issue"});
                }else if(result.rows[0].role !== "user")
                {
                    logger.info(req.headers.username + " not qualified to access endpoint. Client: " + req.clientIp);
                    return res.status(500).send({"status": 500, "message": "Not Qualified to Access Endpoint"});
                }else
                {
                    var date1 = new Date();
                    var date2 = new Date(result.rows[0].timestop);
                    var timeDiff = date1.getTime() - date2.getTime();
                    var dif = timeDiff / 1000;
                    if(dif >= 1)
                    {
                        logger.info("Time out. Please login again. " + req.clientIp);
                        return res.status(500).send({"status": 500, "message": "Time Out. Please Login."});
                    }else
                    {
                        var id = req.body.id;
                        var billmenuname = req.body.billmenuname;
                        var menu = req.body.menu;
                        var addedby = req.cookies.username;
                        var maker = req.cookies.username;
                        var namecreated = req.cookies.username;
                        var namemodified = req.cookies.username;
                        var datecreated = datetime();
                        var datemodified = datetime();
                        
                        //console.log(req.body)
                        if(req.body.edit === 'true')
                        {
                            const query =
                            "UPDATE billsmenu SET billmenuname = $1, menu = $2, addedby = $3, maker = $4, ifavailable = $5, checker = $6, namemodified = $7, datemodified = $8"
                            + " WHERE id = $9";
                            pool.query(query, [billmenuname, menu, addedby, maker, "False", " ", namemodified, datemodified, id], (err,  results) => {    
                                if (err) 
                                {
                                    logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                                    res.status(500).send({"status": 500, "message": "An error occurred. Retry Later."});
                                }
                                else
                                {
                                    return res.status(200).send({"status": 200, "message": "Update Successful."});
                                }
                            });
                        }else
                        {
                            const query =
                                "INSERT INTO billsmenu (billmenuname, menu, addedby, maker, ifavailable, checker, namecreated, datecreated) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
                            pool.query(query, [billmenuname, menu, addedby, maker, "true", " ", namecreated, datecreated], (err,  results) => {    
                                if (err) 
                                {
                                    logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                                    res.status(500).send({"status": 500, "message": "An error occurred. Retry Later."});
                                }
                                else
                                {
                                    return res.status(200).send({"status": 200, "message": "Successfully Added."});
                                }
                            });
                        }
                    }
                }
            }
        });
    }catch(e)
    {
        logger.info(e);
        logger.info("Having Issues with User Delete " + req.clientIp);
        res.status(500).send({"status": 500, "message": "Runtime error occurred. Try Later."});
    }
});

String.prototype.replaceAll = function(search, replace)
{
    if (replace === undefined) {
        return this.toString();
    }

    return this.replace(new RegExp('[' + search + ']', 'g'), replace);
};

function parseLabels(label)
{
    var txnarr = [];
    var txntxt = "";
    var lab = JSON.parse(label);
    for(var i = 0; i < lab.length; i++)
    {
        txntxt += "labelname - " + lab[i].labelname;
        txntxt += "###value - " + lab[i].value;
        txntxt += "###inputtype - " + lab[i].inputtype;
        txntxt += "###lengthrule - " + lab[i].lengthrule;
        txntxt += "###revalidate - " + lab[i].revalidate;
        txntxt += "###capturetoken - " + lab[i].capturetoken;
        txntxt += "###printvalue - " + lab[i].printvalue;
        txnarr.push(txntxt);
        txntxt = "";
    }
    return txnarr.toString();
}

function parseProducts(label)
{
    var txnarr = [];
    var txntxt = "";
    var lab = JSON.parse(label);
    for(var i = 0; i < lab.length; i++)
    {
        txntxt += "productname - " + lab[i].productname;
        txntxt += "###value - " + lab[i].value;
        txnarr.push(txntxt);
        txntxt = "";
    }
    return txnarr.toString();
}

router.get("/download/:id", function(req, res)
{
    try
    {
        var obj = new Object();
        var id = req.params.id;
        logger.info("Bills Download Request For: " + id + ". Ip: " + req.clientIp);
        const termConfig =
            `SELECT * FROM billsmenu q WHERE id = $1`;
        pool.query(termConfig, [id], (err,  billsm) => {    
            if (err) 
            {
                logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
                obj.status = 500;
                obj.message = "Database Query Error. Retry Later.";
                obj.errordata = null
                res.header("Content-Type",'application/json').status(500).send(obj);
            }
            else
            {
                if(billsm.rows[0] === null || billsm.rows[0] === undefined)
                {
                    obj.status = 200;
                    obj.message = "BillsMenu does not exist.";
                    obj.errordata = null;
                    res.header("Content-Type",'application/json').status(500).send(obj);
                }else
                {
                    obj.billsmenuname = billsm.rows[0].billmenuname;
                    var menu = JSON.parse(billsm.rows[0].menu);
                    var steps = 0;
                    var bil = [];
                    var fin = [];
                    var flatten = require('flattree').flatten;
                    flatten(menu, { openAllNodes: true }).forEach((node, index) => {
                        const { state, label = '', children = [] } = node;
                        const { depth, open, path, prefixMask } = state;
                    
                        if (depth === 0) {
                            //console.log('%s (%s)', label, path);
                            if(node.type === 'biller')
                            {
                                var ind = bil.indexOf(node.text);
                                if(ind < 0)
                                    bil.push(node.text);
                            }
                            var pp = node.getParent();
                            var base = "";
                            base += "step - " + steps.toString() + "###id - " + node.id + "###text - " + node.text + "###type - " + node.type 
                                + "###backid - " + pp.id + "###backname - " + pp.text + "###";
                            fin.push(base);
                            steps++;
                            return;
                        }
                    
                        const prefix = prefixMask.substr(1).split('')
                            .map(s => (Number(s) === 0) ? '  ' : '| ')
                            .join('');
                        //console.log('%s%s─%s %s (%s)', prefix, (node.isLastChild() ? '└' : '├'), (node.hasChildren() && open ? '┬' : '─'), label, path);
                        if(node.type === 'biller')
                        {
                            var ind = bil.indexOf(node.text);
                            if(ind < 0)
                                bil.push(node.text);
                        }
                        var pp = node.getParent();
                        var base = "";
                        base += "step - " + steps.toString() + "###id - " + node.id + "###text - " + node.text + "###type - " + node.type 
                            + "###backid - " + pp.id + "###backname - " + pp.text + "###";
                        fin.push(base);
                        steps++;
                    });

                    
                    if(bil !== null)
                    {
                        var use = ""
                        for(var j = 0; j < bil.length; j++)
                        {
                            if(j == 0)
                                use = " WHERE billername = '" + bil[j] + "' AND ifavailable = 'true'";
                            else
                                use += " OR billername = '" + bil[j] + "' AND ifavailable = 'true'";
                        }
                        const txn =
                            `SELECT * FROM billers ` + use + ";"
                        pool.query(txn, (err,  bills) => {    
                            if (err) 
                            {
                                //console.log(err)
                                logger.error("Bills Database Error from: " + req.clientIp + ". Error Occurred ");
                                obj.flow = fin.toString();
                                obj.billers = null;
                                obj.steps = steps;
                                obj.status = 200;
                                obj.message = "Success.";
                                res.header("Content-Type",'application/json').status(200).send(obj);
                            }
                            else
                            {
                                if(bills.rows[0] === null)
                                {
                                    logger.error("No Bills to Download for: " + req.clientIp + ".");
                                    obj.flow = fin.toString();
                                    obj.billers = null;
                                    obj.steps = steps;
                                    obj.status = 200;
                                    obj.message = "Success.";
                                    res.header("Content-Type",'application/json').status(200).send(obj);
                                }
                                else
                                {
                                    var txnarr = [];
                                    var txntxt = "";
                                    
                                    for(var i = 0; i < bills.rows.length; i++)
                                    {
                                        txntxt += "billername - " + bills.rows[i].billername;
                                        txntxt += "###printall - " + bills.rows[i].printall
                                        txntxt += "###vendorid - " + bills.rows[i].vendorid
                                        txntxt += "###istoken - " + bills.rows[i].istoken
                                        txntxt += "###conveniencefee - " + bills.rows[i].conveniencefee
                                        txntxt += "###printvalidation - " + bills.rows[i].printvalidation
                                        txntxt += "###labels - " + parseLabels(bills.rows[i].labels);
                                        txntxt += "###products - " + parseProducts(bills.rows[i].products);
                                        txnarr.push(txntxt);
                                        txntxt = "";
                                    }
                                    obj.billers = txnarr.toString();
                                    obj.flow = fin.toString();
                                    obj.steps = steps;
                                    obj.status = 200;
                                    obj.message = "Success.";
                                    res.header("Content-Type",'application/json').status(200).send(obj);
                                }
                            }
                        });
                    }else
                    {
                        obj.flow = fin.toString();
                        obj.billers = null;
                        obj.steps = steps;
                        obj.status = 200;
                        obj.message = "Success.";
                        res.header("Content-Type",'application/json').status(200).send(obj);
                    }
                }
            }
        });
    }catch(e)
    {
        logger.error("Bills Download from: " + req.clientIp + ". Error Occurred ");
        res.header("Content-Type",'application/json').status(500).send({});
    }
});

module.exports.router = router;