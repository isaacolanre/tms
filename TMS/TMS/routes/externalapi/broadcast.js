var router = express.Router();

var request = require('request').defaults({ rejectUnauthorized: false })


function sendTid(tid, json)
{
	td = tid.slice(1, 4);
	var qry = "SELECT * FROM callhomeroutes WHERE bankcode = $1";
	pool.query(qry, [td], (err, result) => 
	{
		if (err) 
		{
			logger.info('Error Occured');
			return;
		}else
		{
			logger.info("SENDING TO BANK");
			if(result.rows.length < 1)
			{
				logger.info('No Bank is listening');
				return;
			}else
			{
				if(result.rows[0].merchantid.length == 0)
				{
					logger.info("FORWARDING TO BANK");
					var clientServerOptions = {
						uri: result.rows[0].protocol + result.rows[0].destinationip + ':' + result.rows[0].destinationport + result.rows[0].url,
						body: JSON.stringify(json),
						method: 'POST',
						headers: {
							'Content-Type': 'application/json'
						}
					}
					//logger.info("Bank Settings: " + JSON.stringify(clientServerOptions));
					request(clientServerOptions, function (error, response) {
						if(error)
						{
							logger.info("RESPONSE TID: " + tid + ". An error occurred while forwarding to bank: " + error);
							//continue;
						}
						if(response)
						{
							logger.info("RESPONSE TID: " + tid + ". Response From Bank: " + response.body);
							return;
						}
					});
				}
			}
		}
	});
}

function sendMid(mid, json)
{
	var qry = "SELECT * FROM callhomeroutes WHERE merchantid = $1";
	pool.query(qry, [mid], (err, result) => 
	{
		if (err) 
		{
			logger.info('Mid Error Occured');
			return;
		}else
		{
			if(result.rows.length < 1)
			{
				logger.info('No merchant is listening');
				return;
			}else
			{
				logger.info("SENDING TO MERCHANT");
				var clientServerOptions = {
					uri: result.rows[0].protocol + result.rows[0].destinationip + ':' + result.rows[0].destinationport + result.rows[0].url,
					body: JSON.stringify(json),
					method: 'POST',
					headers: {
						'Content-Type': 'application/json'
					}
				}
				request(clientServerOptions, function (error, response) {
					if(error)
					{
						logger.info("RESPONSE MID: " + mid + ". An error occurred while forwarding to merchant: " + error);
						//continue;
					}
					if(response)
					{
						logger.info("RESPONSE MID: " + mid + ". Response From Merchant: " + response.body);
						return;
					}
				});
			}
		}
	});
}

router.post("/push", function(req, res)
{
	logger.info("Inside Push Request");
	req.setTimeout(30000); //set a 30s timeout for this request
	try
    {
		var currentTime = new Date();
    	var year = currentTime.getFullYear();
    	logger.info("Push message gotten from:  " + req.clientIp);
		var json = JSON.parse(JSON.stringify(req.body));
		var state = json.terminalInformation.state;
		logger.info("TID TO BROADCAST: " + state.tid);
		logger.info("MID TO BROADCAST: " + state.mid);
		sendTid(state.tid, json);
		sendMid(state.mid, json);
		if(!state)
		{
			var obj = new Object();
			obj.success = false;
			obj.result = null;
			var error = new Object();
			error.message = "The terminal state message is empty.";
			error.code = 0;
			arr = [];
			arr.push(error);
			obj.errors = arr;
			logger.info("Push message format error from:  " + req.clientIp + " not stored");
			res.header("Content-Type",'application/json').status(400).send(obj);
		}else
		{        
			pool.query("INSERT INTO terminal_state(serial_number, battery_level, "
					+ "charge_status, printer_state, terminal_id, comms_method, cell_station_information, "
					+ "terminal_model_name, terminal_manufacturer, has_battery, software_version, last_transaction_attempt_time, processed_pads, date, merchant_id, year"
					+ ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)", 
					[   state.serial, parseInt(state.bl),
						state.cs, state.ps, state.tid, state.coms, state.cloc, state.tmn,
						state.tmanu, state.hb, state.sv, state.lTxnAt, state.pads, state.ctime, state.mid, year
					], (err, result) => {
				if (err)
				{
					var obj = new Object();
					obj.success = false;
					obj.result = null;
					var error = new Object();
					error.message = "Database Error while storing Terminal State";
					error.code = 0;
					error.remarks = "Nothing was saved. Retry again.";
					arr = [];
					arr.push(error);
					obj.errors = arr;
					logger.info("Push message from:  " + req.clientIp + " not stored");
					res.header("Content-Type",'application/json').status(400).send(obj);
				}
				else
				{
					const query5 =
						"UPDATE terminalconfiguration SET terminalmanufacturer = $1, terminalmodel = $2, serialnumber = $3," + 
						"initapplicationversion = $4  WHERE tid = $5";
					pool.query(query5, [state.tmanu, state.tmn, state.serial, state.sv, state.tid], (err,  results) => 
					{    
						if (err) 
						{
							logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
							res.status(500).send({"status": 500, "message": "An error occurred. Retry Later."});
						}
						else
						{
							var ejournals = json.terminalInformation.ejournals
							if(!ejournals.ejournal.length)
							{
								var obj = new Object();
								obj.success = true;
								obj.result = true;
								var error = new Object();
								error.message = "The ejournal message is empty. Terminal State Saved.";
								error.code = 0;
								arr = [];
								arr.push(error);
								obj.errors = arr;
								logger.info("Push message empty ejournal from:  " + req.clientIp + " not stored");
								res.header("Content-Type",'application/json').status(200).send(obj);
							}else
							{
								var qry6 = "SELECT * FROM terminalconfiguration where ifavailable = $1 AND tid = $2";
                        		pool.query(qry6, ["true", state.tid], (err,  results) => 
								{    
									if (err) 
									{
										logger.info("Database connection error: " + err + ". Time: " + new Date().toLocaleString());
										return res.status(500).send({"status": 500, "message": "An error occurred. Retry Later."});
									}else
									{
										var ejarr = ejournals.ejournal;
										arrValue = [];
										val = 1;
										strg = "";
										main = "(stan, extras, paymentmethod, aid, card_expiry, card_holder, card_type, mid, " + 
										"hashed_pan, masked_pan, rrn, auth_code, amount, date_trans, " + 
										"mti, processing_code, response_code, tap, response_received, receipt_printed, " +
										"validation_method, original_stan, original_rrn, original_auth_code, terminal_id, " + 
										"merchant_id, tmo, sanef, merchant_pin_used, year" +
										") VALUES ";
										for(var i = 0; i < ejarr.length; i++)
										{
											strg += "(";
											arrValue.push(ejarr[i].stan);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].extras);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].paymentmethod);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].aid);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].card_expiry);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].card_holder);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].card_type);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].mid);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].hPan);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].mPan);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].rrn);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].acode);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].amount);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].timestamp);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].mti);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].ps);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].resp);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].tap);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].rr);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].rep);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].vm);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].ostan);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].orrn);
											strg += "$" + val.toString() + ",";
											val++; 
											arrValue.push(ejarr[i].oacode);
											strg += "$" + val.toString() + ",";
											val++; 
											arrValue.push(ejarr[i].tid);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(ejarr[i].mid);
											strg += "$" + val.toString() + ",";
											val++;
											//tmo
											if (("tmo" in ejarr[i])==true)
											{
												arrValue.push(ejarr[i].tmo);
												strg += "$" + val.toString() + ",";
												val++;
											}else
											{
												arrValue.push("");
												strg += "$" + val.toString() + ",";
												val++;
											}
											//sanef
											if (("sanef" in ejarr[i])==true)
											{
												arrValue.push(ejarr[i].sanef);
												strg += "$" + val.toString() + ",";
												val++;
											}else
											{
												arrValue.push("");
												strg += "$" + val.toString() + ",";
												val++;
											}

											arrValue.push(ejarr[i].mPin);
											strg += "$" + val.toString() + ",";
											val++;
											arrValue.push(year);
											strg += "$" + val.toString() + "";
											val++;
											if((i + 1) === ejarr.length)
												strg += ")";
											else
												strg += "),";
										}
										pool.query("INSERT INTO ejournal " + main + strg, arrValue, (err, result) => {
											if (err) 
											{
												logger.info(err);
												var obj = new Object();
												obj.success = false;
												obj.result = null;
												var error = new Object();
												error.message = "Database Error while storing Ejournal";
												error.code = 0;
												error.remarks = "Terminal Health State Stored. Retry again for ejournals";
												arr = [];
												arr.push(error);
												obj.errors = arr;
												logger.info("Ejournal message from:  " + req.clientIp + " not stored");
												res.header("Content-Type",'application/json').status(400).send(obj);
											}
											else
											{
												var obj = new Object();
												obj.success = true;
												obj.result = true;
												var error = new Object();
												error.message = "Successful";
												error.code = 0;
												error.remarks = "Terminal Health State and " + ejarr.length.toString() + " ejournals saved.";
												arr = [];
												arr.push(error);
												obj.errors = arr;
												res.header("Content-Type",'application/json').status(200).send(obj);
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
    }catch(e)
    {
        logger.info(e);
        logger.error("Push message gotten from: " + req.clientIp + ". Error Occurred ");
        res.status(500).send({});
    }
});

module.exports.router = router;