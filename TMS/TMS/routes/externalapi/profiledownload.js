var router = express.Router();
//Main Oga

String.prototype.replaceAll = function(search, replace)
{
    if (replace === undefined) {
        return this.toString();
    }

    return this.replace(new RegExp('[' + search + ']', 'g'), replace);
};

//change to 1.0.7 
//confirm that the condition is met
var currentVersion = "1.0.8";
var forceAllTerminals = "true";//true
var riid = "627787";
var setbank = "0520082938";
//var riid = "627955";
//var setbank = "1007358176";
var agencyip = "85.159.214.73";
var agencyport = "9090";
router.get("/download", function(req, res)
{
    try
    {
		var brand = req.headers.brand;
		var model = req.headers.model;
		var serial = req.headers.serial;
		var appversion = req.headers.appversion;

		logger.info("BRAND: " + brand);
		logger.info("MODEL: " + model);
		logger.info("SERIAL: " + serial);
		logger.info("SERIAL LENGTH: " + serial.length);
		logger.info("APPVERSION: " + appversion);

		if((brand === "AISINO" && appversion !== "1.0.1")
			|| (brand === "AISINO" && appversion !== "1.0.2")
			|| (brand === "AISINO" && appversion !== "1.0.3")
			|| (brand === "AISINO" && appversion !== "1.0.4")
			|| (brand === "AISINO" && appversion !== "1.0.5")
			|| (brand === "AISINO" && appversion !== "1.0.6")
			|| (brand === "AISINO" && appversion !== "1.0.7"))
		{
			logger.info("Please update: " + ". Time: " + new Date().toLocaleString());
			var obj = new Object();
			obj.status = 500;
			obj.message = "Kindly Update Your App.";
			obj.errordata = null;
			return res.header("Content-Type",'application/json').status(500).send(obj);
		}else
		{
			var obj = new Object();
			obj.timestamp = getDateTimeSpec();
			logger.info("Profile Download Request From: Ip: " + req.clientIp);
			const termConfig = "SELECT * FROM stock where serialnumber = $1";
			pool.query(termConfig, [serial], (err,  ddd) => {    
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
					if(serial === 'nelsonulonna@gmail.com' ||
						serial === 'ogunkoyaseyefunmi@gmail.com' ||
						serial === 'obileyetemitope4@gmail.com' ||
						serial === 'temmyfree2rhyme@gmail.com' ||
						serial === 'inyassjamiu@gmail.com' ||
						serial === 'mercyblis@gmail.com' ||
						serial === 'ekeka500@gmail.com' ||
						serial === 'gloryoboh34@gmail.com' ||
						serial === 'ajibolajbl07@gmail.com'||
						serial === 'uchegiftxp@gmail.com'
						)
					{
						console.log("OUTSTANDING DEBT");
						return res.status(500).send({"status": 500, "message": "Outstanding Debt."});
					}else if(ddd.rows.length == 0)
					{
						obj.status = 200;
						obj.message = "Serial Number not recognized.";
						obj.errordata = null;
						res.header("Content-Type",'application/json').status(500).send(obj);
					}else
					{
						var tid = ddd.rows[0].terminalid;
						const query5 =
								"UPDATE terminalconfiguration SET terminalmanufacturer = $1, terminalmodel = $2, serialnumber = $3," + 
								"initapplicationversion = $4 WHERE tid = $5";
						pool.query(query5, [brand, model, serial, appversion, tid], (err,  r) => 
						{    
							if (err) 
							{
								obj.status = 200;
								obj.message = "Tid has issues. Contact Admin";
								obj.errordata = null;
								res.header("Content-Type",'application/json').status(500).send(obj);
							}
							else
							{
								var qry3 =
								"UPDATE stock SET terminalid = $1, appversion = $2" + 
								" WHERE serialnumber = $3";
								pool.query(qry3, [tid, appversion, serial], (err, check) => {
									if (err) 
									{
										logger.error("Channels Profile Put Session Database Issue " + req.clientIp);
										res.status(500).send({"status": 500, "message": "Try Later"});
									}else
									{
										const termConfig = "SELECT * FROM terminalconfiguration where tid = $1 AND ifavailable = $2";
										pool.query(termConfig, [tid, "true"], (err,  config) => {    
											if(config.rows.length == 0)
											{
												obj.status = 200;
												obj.message = "Tid not profiled.";
												obj.errordata = null;
												res.header("Content-Type",'application/json').status(500).send(obj);
											}else
											{
												var tconfig = config.rows[0];
												obj.tid = config.rows[0].tid;
												obj.mid = config.rows[0].mid;
												obj.serialnumber = config.rows[0].serialnumber;
												obj.timestamp = getDateTimeSpec();
												obj.terminalmodel = config.rows[0].terminalmodel;
												obj.initapplicationversion = config.rows[0].initapplicationversion;
												obj.merchantname = config.rows[0].merchantname;
												obj.merchantaddress = config.rows[0].merchantaddress;
												obj.adminpin = config.rows[0].adminpin;
												obj.merchantpin = config.rows[0].merchantpin;
												obj.changepin = config.rows[0].changepin;
												obj.contactname = config.rows[0].contactname;
												obj.contactphone = config.rows[0].contactphone;
												obj.email = config.rows[0].email;
												obj.mcc = config.rows[0].mcc;
												obj.datecreated = config.rows[0].datecreated;
												obj.namecreated = config.rows[0].namecreated;
												obj.datemodified = config.rows[0].datemodified;
												obj.namemodified = config.rows[0].namemodified;
												obj.lga = config.rows[0].lga;
												obj.appname = config.rows[0].appname;
												obj.country = config.rows[0].country;
												obj.countrycode = config.rows[0].countrycode;
												obj.maker = config.rows[0].maker;
												obj.checker = config.rows[0].checker;
												obj.profilename = config.rows[0].profilename;
												obj.terminalmanufacturer = config.rows[0].terminalmanufacturer;
												obj.blocked = config.rows[0].blocked;
												obj.blockedpin = config.rows[0].blockedpin;
												obj.ownerusername = config.rows[0].ownerusername;
												obj.superagent = config.rows[0].superagent;
												obj.dialogheading = config.rows[0].dialogheading;
												obj.simserial = config.rows[0].simserial;
												obj.simnumber = config.rows[0].simnumber;
												obj.simname = config.rows[0].simname;
												obj.accountname = config.rows[0].accountname;
												obj.accountcode = config.rows[0].accountcode;
												obj.accountnumber = config.rows[0].accountnumber;
												obj.accountbank = config.rows[0].accountbank;
												obj.ifavailable = config.rows[0].ifavailable;
												obj.profileid = config.rows[0].profileid;
												obj.ownerusername = config.rows[0].ownerusername;
												
												obj.stampduty = config.rows[0].stampduty;
												obj.msc = config.rows[0].msc;
												obj.switchfee = config.rows[0].switchfee;
												obj.tmsfeerule = config.rows[0].tmsfeerule;
												obj.superagentfeerule = config.rows[0].superagentfeerule;
												obj.ctransferrule = config.rows[0].tmstransferrule;
												obj.satfeerule = config.rows[0].superagenttransferrule;
												obj.tmo = config.rows[0].tmo;
												obj.sanef = config.rows[0].sanefnumber;
												obj.percentagerule = config.rows[0].percentagerule;
												obj.maxamount = config.rows[0].maxamount;
												obj.hostswitchamount = config.rows[0].hostswitchamount;
												obj.superpercentage = config.rows[0].superpercentage;
												obj.currentversion = currentVersion;
												obj.forceallterminals = forceAllTerminals;

												obj.encmstkey = config.rows[0].encmstkey;
												obj.clrmstkey = config.rows[0].clrmstkey;
												obj.encseskey = config.rows[0].encseskey;
												obj.clrseskey = config.rows[0].clrseskey;
												obj.encpinkey = config.rows[0].encpinkey;
												obj.clrpinkey = config.rows[0].clrpinkey;
												obj.paramdownload = config.rows[0].paramdownload;
												


												//
												obj.iswtid = config.rows[0].iswtid;
												obj.iswmid = config.rows[0].iswmid;
												obj.wdcapped = config.rows[0].wdcapped;
												obj.wdsharesa = config.rows[0].wdsharesa;
												obj.wdsharess = config.rows[0].wdsharess;
												obj.cttms = config.rows[0].cttms;
												obj.ctsuperagent = config.rows[0].ctsuperagent;
												obj.ctsupersuperagent = config.rows[0].ctsupersuperagent;
												obj.wtsupersuper = config.rows[0].wtsupersuper;

												obj.riid = riid;
												obj.setbank = setbank;

												if(config.rows[0].tid === "2082OM54")
												{
													obj.riid = "627787";
													obj.setbank = "0520082938";
												}
												
												obj.agencyip = agencyip;
												obj.agencyport = agencyport;

												const appl =
													`SELECT * FROM terminalapplications WHERE brand = $1 AND model = $2`;
												pool.query(appl, [brand, model], (err,  applic) => {    
													if (err) 
													{
														obj.status = 200;
														obj.message = "Tid has terminalapplication issues. Contact Admin";
														obj.data = tconfig;
														return res.header("Content-Type",'application/json').status(500).send(obj);
													}else
													{
														if(applic.rows.length < 1)
														{
															obj.appversion = null;
															obj.appbrand = null;
															obj.appdescription = null;
															obj.appmodel = null;
															obj.appfix = null;
															obj.appterminals = null;
															obj.appupdated = null;
															obj.appremarks = null;
														}
														else
														{
															var ap = applic.rows;
															for(var i = 0; i < ap.length; i++)
															{
																if (ap[i].terminals.indexOf("ALL " + brand + " TERMINALS") >= 0) 
																{
																	obj.appversion = applic.rows[i].version;
																	obj.appbrand = applic.rows[i].brand;
																	obj.appdescription = applic.rows[i].description;
																	obj.appmodel = applic.rows[i].model;
																	obj.appfix = applic.rows[i].fix;
																	obj.appterminals = applic.rows[i].terminals;
																	obj.appupdated = applic.rows[i].updated;
																	obj.appremarks = applic.rows[i].remarks;
																	break;
																} else if(ap[i].terminals.indexOf(tid) >= 0) 
																{
																	obj.appversion = applic.rows[i].version;
																	obj.appbrand = applic.rows[i].brand;
																	obj.appdescription = applic.rows[i].description;
																	obj.appmodel = applic.rows[i].model;
																	obj.appfix = applic.rows[i].fix;
																	obj.appterminals = applic.rows[i].terminals;
																	obj.appupdated = applic.rows[i].updated;
																	obj.appremarks = applic.rows[i].remarks;
																	break;
																}
															}
															if(appversion === obj.appversion)
															{
																obj.appversion = null;
																obj.appbrand = null;
																obj.appdescription = null;
																obj.appmodel = null;
																obj.appfix = null;
																obj.appterminals = null;
																obj.appupdated = null;
																obj.appremarks = null;
															}
														}

														const pro =
															"SELECT * FROM profile WHERE id = $1 AND ifavailable = $2";
														pool.query(pro, [obj.profileid, "true"], (err,  profile) => { 
															if (err) 
															{
																obj.status = 200;
																obj.message = "Tid has Profile issues. Contact Admin";
																obj.errordata = null;
																res.header("Content-Type",'application/json').status(500).send(obj);
															}
															else
															{
																if(profile.rows.length < 1)
																{
																	obj.status = 200;
																	obj.message = "Tid has Profile issues. Contact Admin";
																	obj.errordata = null;
																	return res.header("Content-Type",'application/json').status(500).send(obj);
																}
																obj.profilename = profile.rows[0].name;
																obj.profileremarks = profile.rows[0].remarks;
																obj.profilecallhomeid = profile.rows[0].callhomeid;
																obj.profilecommsid = profile.rows[0].commsid;
																obj.profilereceiptid = profile.rows[0].receiptid;
																obj.profilehostid = profile.rows[0].hostid;
																obj.profileswitchkeyid = profile.rows[0].switchkeyid;
																obj.profilecurrencyid = profile.rows[0].currencyid;
																obj.profilebankid = profile.rows[0].bankid;
																obj.profiletransactiontypesarray = profile.rows[0].transactiontypesarray;
																obj.profilecardschemekeytypes = profile.rows[0].cardschemekeytypes;
																obj.profilevas = profile.rows[0].vas;
																obj.profileprotectlist = profile.rows[0].protectlist;
																obj.profileotherimportant = profile.rows[0].otherimportant;
																obj.profilehost2id = profile.rows[0].host2id;
																obj.profilefswitchkeyid = profile.rows[0].fswitchkeyid;
																obj.profilerlogoid = profile.rows[0].rlogoid;
																obj.profileblogoid = profile.rows[0].blogoid;
																obj.profilehostarray = profile.rows[0].hostarray;
																obj.profiletmspay = profile.rows[0].tmspay;
																
																const ce =
																	"SELECT * FROM callhome WHERE id = $1";
																pool.query(ce, [obj.profilecallhomeid], (err,  ch) => { 
																	if (err) 
																	{
																		obj.status = 200;
																		obj.message = "Tid has Profile issues. Contact Admin";
																		obj.errordata = null;
																		res.header("Content-Type",'application/json').status(500).send(obj);
																	}
																	else
																	{
																		if(ch.rows.length < 1)
																		{
																			obj.status = 200;
																			obj.message = "1x Tid has Callhome issues. Contact Admin";
																			obj.errordata = null;
																			return res.header("Content-Type",'application/json').status(500).send(obj);
																		}else
																		{
																			obj.chname = ch.rows[0].name;
																			obj.chinterval = ch.rows[0].interval;
																			obj.chip = ch.rows[0].ip;
																			obj.chport = ch.rows[0].port;
																			obj.chremotedownloadtime = ch.rows[0].remotedownloadtime;
																			obj.chcount = ch.rows[0].count;
																			
																			const cc =
																				"SELECT * FROM comms WHERE id = $1";
																			pool.query(cc, [obj.profilecommsid], (err,  com) => { 
																				if (err) 
																				{
																					obj.status = 200;
																					obj.message = "Tid has Profile issues. Contact Admin";
																					obj.errordata = null;
																					return res.header("Content-Type",'application/json').status(500).send(obj);
																				}
																				else
																				{
																					if(com.rows.length < 1)
																					{
																						obj.status = 200;
																						obj.message = "1ax Tid has Callhome issues. Contact Admin";
																						obj.errordata = null;
																						return res.header("Content-Type",'application/json').status(500).send(obj);
																					}else
																					{
																						obj.comname = com.rows[0].name;
																						obj.comusername = com.rows[0].username;
																						obj.comgateway = com.rows[0].gateway;
																						obj.comip = com.rows[0].ip;
																						obj.comport = com.rows[0].port;
																						obj.comapn = com.rows[0].apn;
																						obj.compassword = com.rows[0].password;
																						obj.comremarks = com.rows[0].remarks;
																						obj.comcommstype = com.rows[0].commstype;
																						obj.comipmode = com.rows[0].ipmode;
																						
																						const rp =
																							"SELECT * FROM receipt WHERE id = $1";
																						pool.query(rp, [obj.profilereceiptid], (err,  rpt) => { 
																							if (err) 
																							{
																								obj.status = 200;
																								obj.message = "Tid has Profile issues. Contact Admin";
																								obj.errordata = null;
																								res.header("Content-Type",'application/json').status(500).send(obj);
																							}
																							else
																							{
																								if(rpt.rows.length < 1)
																								{
																									obj.status = 200;
																									obj.message = "1ac Tid has Callhome issues. Contact Admin";
																									obj.errordata = null;
																									return res.header("Content-Type",'application/json').status(500).send(obj);
																								}else
																								{
																									obj.rptname = rpt.rows[0].name;
																									obj.rptfootertext = rpt.rows[0].footertext;
																									obj.rptcustomercopylabel = rpt.rows[0].customercopylabel;
																									obj.rptmerchantcopylabel = rpt.rows[0].merchantcopylabel;
																									obj.rptfootnotelabel = rpt.rows[0].footnotelabel;
																									obj.rptnormalfontsize = rpt.rows[0].normalfontsize;
																									obj.rptheaderfontsize = rpt.rows[0].headerfontsize;
																									obj.rptamountfontsize = rpt.rows[0].amountfontsize;
																									obj.rptprintmerchantcopynumber = rpt.rows[0].printmerchantcopynumber;
																									obj.rptprintclientcopynumber = rpt.rows[0].printclientcopynumber;
																									obj.rptshowlogo = rpt.rows[0].showlogo;
																									obj.rptshowbarcode = rpt.rows[0].showbarcode;
																									obj.rptsaveforreceipt = rpt.rows[0].saveforreceipt;

																									const hi =
																										"SELECT * FROM host WHERE id = $1";
																									pool.query(hi, [obj.profilehostid], (err,  hostid) => { 
																										if (err) 
																										{
																											obj.status = 200;
																											obj.message = "Tid has Profile issues. Contact Admin";
																											obj.errordata = null;
																											res.header("Content-Type",'application/json').status(500).send(obj);
																										}
																										else
																										{
																											if(hostid.rows.length < 1)
																											{
																												obj.status = 200;
																												obj.message = "1ad Tid has Callhome issues. Contact Admin";
																												obj.errordata = null;
																												return res.header("Content-Type",'application/json').status(500).send(obj);
																											}else
																											{
																												obj.hostidname = hostid.rows[0].name;
																												obj.hostip = hostid.rows[0].ip;
																												obj.hostport = hostid.rows[0].port;
																												obj.hostssl = hostid.rows[0].ssl;
																												obj.hostfriendlyname = hostid.rows[0].friendlyname;
																												obj.hostmestype = hostid.rows[0].mestype;

																												
																												const sk =
																													"SELECT * FROM keys WHERE id = $1";
																												pool.query(sk, [obj.profileswitchkeyid], (err,  swk) => { 
																													if (err) 
																													{
																														obj.status = 200;
																														obj.message = "Tid has Profile issues. Contact Admin";
																														obj.errordata = null;
																														res.header("Content-Type",'application/json').status(500).send(obj);
																													}
																													else
																													{
																														if(swk.rows.length < 1)
																														{
																															obj.status = 200;
																															obj.message = "1ae Tid has Callhome issues. Contact Admin";
																															obj.errordata = null;
																															return res.header("Content-Type",'application/json').status(500).send(obj);
																														}else
																														{
																															obj.swkname = swk.rows[0].name;
																															obj.swkcomponent1 = swk.rows[0].component1;
																															obj.swkcomponent2 = swk.rows[0].component2;
																															
																															const cu =
																																"SELECT * FROM currency WHERE id = $1";
																															pool.query(cu, [obj.profilecurrencyid], (err,  cur) => { 
																																if (err) 
																																{
																																	obj.status = 200;
																																	obj.message = "Tid has Profile issues. Contact Admin";
																																	obj.errordata = null;
																																	res.header("Content-Type",'application/json').status(500).send(obj);
																																}
																																else
																																{
																																	if(cur.rows.length < 1)
																																	{
																																		obj.status = 200;
																																		obj.message = "1af Tid has Callhome issues. Contact Admin";
																																		obj.errordata = null;
																																		return res.header("Content-Type",'application/json').status(500).send(obj);
																																	}else
																																	{
																																		obj.curname =  cur.rows[0].name;
																																		obj.curabbreviation =  cur.rows[0].abbreviation;
																																		obj.curcode =  cur.rows[0].code;
																																		obj.curminorunit =  cur.rows[0].minorunit;
																																		obj.curremarks =  cur.rows[0].remarks;
																																		
																																		const bn =
																																			"SELECT * FROM banks WHERE id = $1";
																																		pool.query(bn, [obj.profilebankid], (err,  bnk) => { 
																																			if (err) 
																																			{
																																				obj.status = 200;
																																				obj.message = "Tid has Profile issues. Contact Admin";
																																				obj.errordata = null;
																																				return res.header("Content-Type",'application/json').status(500).send(obj);
																																			}
																																			else
																																			{
																																				if(bnk.rows.length < 1)
																																				{
																																					obj.status = 200;
																																					obj.message = "1ag Tid has Callhome issues. Contact Admin";
																																					obj.errordata = null;
																																					return res.header("Content-Type",'application/json').status(500).send(obj);
																																				}else
																																				{
																																					obj.bnkname =  bnk.rows[0].name;
																																					obj.bnkcode =  bnk.rows[0].code;
																																					obj.bnkremarks =  bnk.rows[0].remarks;
																																					
																																					var tt = obj.profiletransactiontypesarray;
																																					var str = [];
																																					var init = "";
																																					for(var i = 0; i < tt.length; i++)
																																					{
																																						if(tt[i] === '#')
																																						{
																																							str.push(parseInt(init));
																																							init = "";
																																							continue;
																																						}else
																																						{
																																							init = init + tt[i];
																																							continue;
																																						}
																																					}
																																					
																																					if(str.length > 0)
																																					{
																																						var use = ""
																																						for(var j = 0; j < str.length; j++)
																																						{
																																							if(j == 0)
																																								use = " WHERE id = " + str[j]
																																							else
																																								use += " OR id = " + str[j]
																																						}
																																						var ttypes =
																																						"SELECT * FROM transactiontype " + use + " ORDER BY position ASC;";
																																						pool.query(ttypes, (err,  types) => {    
																																							if (err) 
																																							{
																																								obj.status = 200;
																																								obj.message = "Tid has transaction issues. Contact Admin";
																																								obj.errordata = tconfig;
																																								return res.header("Content-Type",'application/json').status(500).send(obj);
																																							}else
																																							{
																																								if(types.rows.length < 1)
																																								{
																																									obj.status = 200;
																																									obj.message = "Success. No Transaction Type";
																																									obj.data = tconfig;
																																									return res.header("Content-Type",'application/json').status(500).send(obj);
																																								}
																																								else
																																								{
																																									var txnarr = [];
																																									var txntxt = "";
																																									
																																									for(var i = 0; i < types.rows.length; i++)
																																									{
																																										txntxt += "name - " + types.rows[i].name;
																																										txntxt += "###common - " + types.rows[i].commonname;
																																										txntxt += "###transtype - " + types.rows[i].transtype;
																																										txntxt += "###uses - " + types.rows[i].uses
																																										txntxt += "###position - " + types.rows[i].position
																																										txntxt += "###discountpercent - " + types.rows[i].discountpercent
																																										txntxt += "###discount - " + types.rows[i].discount
																																										txntxt += "###commissionpercent - " + types.rows[i].commissionpercent
																																										txntxt += "###commission - " + types.rows[i].commission
																																										txntxt += "###baseamtpercentage - " + types.rows[i].baseamtpercentage
																																										txntxt += "###baseamtfixed - " + types.rows[i].baseamtfixed
																																										txntxt += "###remarks - " + types.rows[i].remarks
																																										txnarr.push(txntxt);
																																										txntxt = "";
																																									}
																																									
																																									obj.transactions = txnarr.toString();
																																									
																																									var ha = obj.profilehostarray;
																																									var arry3 = [];
																																									var arry4 = [];
																																									var ar3 = "";
																																									var ar4 = "";
																																									var loop = 0;
																																									if(ha)
																																									{
																																										for(var j = 0; j < ha.length; j++)
																																										{
																																											if(ha.charAt(j) === '#')
																																											{
																																												loop = 0;
																																												arry4.push(ar4);
																																												ar4 = "";
																																											}else if(ha.charAt(j) === ' ')
																																											{
																																												loop = 1;
																																												arry3.push(parseInt(ar3));
																																												ar3 = "";
																																												j += 2;
																																											}else
																																											{
																																												if(loop === 0)
																																												{
																																													ar3 += ha.charAt(j);
																																												}else
																																												{
																																													ar4 += ha.charAt(j);
																																												}
																																											}
																																										}
																																									}

																																									const tta =
																																										`SELECT name, position FROM transactiontype ORDER BY position ASC`;
																																									pool.query(tta, (err,  ttar) => {    
																																										if (err) 
																																										{
																																											console.log(err);
																																											obj.status = 200;
																																											obj.message = "Success. Transaction Host Error";
																																											obj.data = tconfig;
																																											return res.header("Content-Type",'application/json').status(500).send(obj);
																																										}
																																										else
																																										{
																																											var harr2 = [];
																																											var htxt2 = "";
																																											var ejo = ttar.rows;
																																											for(var j = 0; j < ejo.length; j++) 
																																											{
																																												var ch = ejo[j].id;
																																												var k = arry3.indexOf(ch);
																																												
																																												if(arry4[k] === 'h2')
																																												{
																																													htxt2 += ejo[j].name;
																																													htxt2 += "###host2###"
																																													harr2.push(htxt2);
																																													htxt2 = "";
																																												}else
																																												{
																																													htxt2 += ejo[j].name;
																																													htxt2 += "###host1###"
																																													harr2.push(htxt2);
																																													htxt2 = "";
																																												}
																																											}
																																											obj.hostarray = harr2.toString();

																																											
																																											var zz = obj.profileprotectlist;
																																											var str2 = [];
																																											var init2 = "";
																																											if(zz !== null)
																																											{
																																												for(var i = 0; i < zz.length; i++)
																																												{
																																													if(zz[i] === '#')
																																													{
																																														str2.push(parseInt(init2));
																																														init2 = "";
																																														continue;
																																													}else
																																													{
																																														init2 = init2 + zz[i];
																																														continue;
																																													}
																																												}
																																											}
																																											
																																											
																																											if(str2.length > 0)
																																											{
																																												var use = ""
																																												for(var j = 0; j < str2.length; j++)
																																												{
																																													if(j == 0)
																																														use = " WHERE id = " + str2[j]
																																													else
																																														use += " OR id = " + str2[j]
																																												}
																																												var ttypes2 =
																																														"SELECT name FROM transactiontype " + use + ";";
																																												pool.query(ttypes2, (err,  types2) => { 
																																													if (err) 
																																													{
																																														obj.status = 200;
																																														obj.message = "Success. Transaction Type Error";
																																														obj.data = tconfig;
																																														return res.header("Content-Type",'application/json').status(500).send(obj);
																																													}
																																													else
																																													{
																																														if(types2.rows.length > 0)
																																														{
																																															var txnarr2 = [];
																																															var txntxt2 = "";
																																															
																																															for(var i = 0; i < types2.rows.length; i++)
																																															{
																																																txntxt2 += "name - " + types2.rows[i].name;
																																																txntxt2 += "###"
																																																txnarr2.push(txntxt2);
																																																txntxt2 = "";
																																															}
																																															obj.protectlist = txnarr2.toString();

																																															
																																															const h2 =
																																																"SELECT * FROM host WHERE id = $1";
																																															pool.query(h2, [obj.profilehost2id], (err,  hostid2) => { 
																																																if (err) 
																																																{
																																																	obj.status = 200;
																																																	obj.message = "Tid has Profile issues. Contact Admin";
																																																	obj.errordata = null;
																																																	res.header("Content-Type",'application/json').status(500).send(obj);
																																																}
																																																else
																																																{
																																																	if(hostid2.rows.length < 1)
																																																	{
																																																		obj.status = 200;
																																																		obj.message = "iap Tid has Callhome issues. Contact Admin";
																																																		obj.errordata = null;
																																																		return res.header("Content-Type",'application/json').status(500).send(obj);
																																																	}else
																																																	{
																																																		obj.hostid2name = hostid2.rows[0].name;
																																																		obj.host2ip = hostid2.rows[0].ip;
																																																		obj.host2port = hostid2.rows[0].port;
																																																		obj.host2ssl = hostid2.rows[0].ssl;
																																																		obj.host2friendlyname = hostid2.rows[0].friendlyname;
																																																		obj.host2mestype = hostid2.rows[0].mestype;
																																																		
																																																		const sk2 =
																																																			"SELECT * FROM keys WHERE id = $1";
																																																		pool.query(sk2, [obj.profilefswitchkeyid], (err,  swk2) => { 
																																																			if (err) 
																																																			{
																																																				obj.status = 200;
																																																				obj.message = "Tid has Profile issues. Contact Admin";
																																																				obj.errordata = null;
																																																				res.header("Content-Type",'application/json').status(500).send(obj);
																																																			}
																																																			else
																																																			{
																																																				if(swk2.rows.length < 1)
																																																				{
																																																					obj.status = 200;
																																																					obj.message = "1am Tid has Callhome issues. Contact Admin";
																																																					obj.errordata = null;
																																																					return res.header("Content-Type",'application/json').status(500).send(obj);
																																																				}else
																																																				{
																																																					obj.swk2name = swk2.rows[0].name;
																																																					obj.swk2component1 = swk2.rows[0].component1;
																																																					obj.swk2component2 = swk2.rows[0].component2;
																																																					
																																																					if(obj.profilerlogoid !== "0")
																																																					{
																																																						const lg =
																																																							"SELECT * FROM logos WHERE id = $1";
																																																						pool.query(lg, [obj.profilerlogoid], (err,  logo) => { 
																																																							if (err) 
																																																							{
																																																								obj.status = 200;
																																																								obj.message = "Tid has Logo issues. Contact Admin";
																																																								obj.errordata = null;
																																																								res.header("Content-Type",'application/json').status(500).send(obj);
																																																							}
																																																							else
																																																							{
																																																								if(logo.rows.length < 1)
																																																								{
																																																									obj.status = 200;
																																																									obj.message = "1an Tid has Callhome issues. Contact Admin";
																																																									obj.errordata = null;
																																																									return res.header("Content-Type",'application/json').status(500).send(obj);
																																																								}else
																																																								{
																																																									obj.logorversion =  logo.rows[0].version;
																																																									obj.logorfilename =  logo.rows[0].filename;
																																																									obj.logordescription =  logo.rows[0].description;
																																																									obj.logorbankname =  logo.rows[0].bankname;
																																																									obj.logorbankcode =  logo.rows[0].bankcode;
																																																									obj.logordownload =  logo.rows[0].download;
																																																									obj.logorisreceipt =  logo.rows[0].isreceipt;
																																																									
																																																									
																																																									if(obj.profileblogoid !== "0")
																																																									{
																																																										const lg =
																																																											"SELECT * FROM logos WHERE id = $1";
																																																										pool.query(lg, [obj.profileblogoid], (err,  logo) => { 
																																																											if (err) 
																																																											{
																																																												obj.status = 200;
																																																												obj.message = "Tid has Logo issues. Contact Admin";
																																																												obj.errordata = null;
																																																												res.header("Content-Type",'application/json').status(500).send(obj);
																																																											}
																																																											else
																																																											{
																																																												if(logo.rows.length < 1)
																																																												{
																																																													obj.status = 200;
																																																													obj.message = "Tid has Callhome issues. Contact Admin";
																																																													obj.errordata = null;
																																																													return res.header("Content-Type",'application/json').status(500).send(obj);
																																																												}else
																																																												{
																																																													obj.logobversion =  logo.rows[0].version;
																																																													obj.logobfilename =  logo.rows[0].filename;
																																																													obj.logobdescription =  logo.rows[0].description;
																																																													obj.logobbankname =  logo.rows[0].bankname;
																																																													obj.logobbankcode =  logo.rows[0].bankcode;
																																																													obj.logobdownload =  logo.rows[0].download;
																																																													obj.logobisreceipt =  logo.rows[0].isreceipt;
																																																													
																																																													obj.status = 200;
																																																													obj.message = "Success";
																																																													return res.header("Content-Type",'application/json').status(200).send(obj);
																																																													
																																																												}
																																																											}
																																																										});
																																																									}else
																																																									{
																																																										obj.status = 200;
																																																										obj.message = "Success";
																																																										return res.header("Content-Type",'application/json').status(200).send(obj);
																																																									}
																																																								}
																																																							}
																																																						});
																																																					}else
																																																					{
																																																						obj.status = 200;
																																																						obj.message = "Success";
																																																						return res.header("Content-Type",'application/json').status(200).send(obj);
																																																					}
																																																					
																																																				}
																																																			}
																																																		});
																																																		
																																																	}
																																																}
																																															});


																																														}
																																													}
																																												});
																																											}else
																																											{
																																												obj.status = 200;
																																												obj.message = "Tid has protectlist issues. Contact Admin";
																																												obj.errordata = tconfig;
																																												return res.header("Content-Type",'application/json').status(500).send(obj);
																																											}	
																																										}
																																									});	
																																								}
																																							}
																																						});
																																						
																																					}else
																																					{
																																						obj.status = 200;
																																						obj.message = "Tid has transaction issues. Contact Admin";
																																						obj.errordata = tconfig;
																																						return res.header("Content-Type",'application/json').status(500).send(obj);
																																					}
																																					
																																				}
																																			}
																																		});
																																		
																																	}
																																}
																															});
																														}
																													}
																												});
																											}
																										}
																									});	
																								}
																							}
																						});
																					}
																				}
																			});
																		}
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
				}
			});
		}
    }catch(e)
    {
        logger.error("Profile Download from: " + req.clientIp + ". Error Occurred ");
        res.header("Content-Type",'application/json').status(500).send({});
    }
});

router.get("/hackeruse", function(req, res)
{
    try
    {
		var brand = req.headers.brand;
		var model = req.headers.model;
		var serial = req.headers.serial;
		var appversion = req.headers.appversion;
		var token = req.headers.token;

		logger.info("BRAND: " + brand);
		logger.info("MODEL: " + model);
		logger.info("SERIAL: " + serial);
		logger.info("SERIAL LENGTH: " + serial.length);
		logger.info("APPVERSION: " + appversion);
		logger.info("Token: " + token);
		
		var qry = "SELECT * FROM tokens WHERE token = $1 AND username = $2";
        pool.query(qry, [token, serial], (err, lol) => {
            if (err) 
            {
                logger.info("tms TOKEN CHECK FAILED FOR " + req.clientIp);
                return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
            }else
            {
                if(lol.rows === undefined || lol.rows.length !== 1)
                {
                    logger.info("Kindly login again " + req.clientIp);
                    return res.status(500).send({"status": 500, "message": "Unauthorized"});
                }else
                {
                    var date1 = new Date();
                    var date2 = new Date(lol.rows[0].timestop);
                    var timeDiff = date1.getTime() - date2.getTime();
                    var dif = timeDiff / 1000;
                    if(dif >= 1)
                    {
                        logger.info("Time out. Please login again. " + req.clientIp);
                        return res.status(500).send({"status": 500, "message": "Time Out. Please Login."});
                    }else
                    {
                        var obj = new Object();
						obj.timestamp = getDateTimeSpec();
						logger.info("Profile Download Request From: Ip: " + req.clientIp);
						const termConfig = "SELECT * FROM stock where serialnumber = $1";
						pool.query(termConfig, [serial], (err,  ddd) => {    
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
								if(serial === 'nelsonulonna@gmail.com' ||
									serial === 'ogunkoyaseyefunmi@gmail.com' ||
									serial === 'obileyetemitope4@gmail.com' ||
									serial === 'temmyfree2rhyme@gmail.com' ||
									serial === 'inyassjamiu@gmail.com' ||
									serial === 'mercyblis@gmail.com' ||
									serial === 'ekeka500@gmail.com' ||
									serial === 'gloryoboh34@gmail.com' ||
									serial === 'ajibolajbl07@gmail.com'
									)
								{
									console.log("OUTSTANDING DEBT");
									return res.status(500).send({"status": 500, "message": "Outstanding Debt."});
								}else if(ddd.rows.length == 0)
								{
									obj.status = 200;
									obj.message = "Serial Number not recognized.";
									obj.errordata = null;
									res.header("Content-Type",'application/json').status(500).send(obj);
								}else
								{
									var tid = ddd.rows[0].terminalid;
									const query5 =
											"UPDATE terminalconfiguration SET terminalmanufacturer = $1, terminalmodel = $2, serialnumber = $3," + 
											"initapplicationversion = $4 WHERE tid = $5";
									pool.query(query5, [brand, model, serial, appversion, tid], (err,  r) => 
									{    
										if (err) 
										{
											obj.status = 200;
											obj.message = "Tid has issues. Contact Admin";
											obj.errordata = null;
											res.header("Content-Type",'application/json').status(500).send(obj);
										}
										else
										{
											var qry3 =
											"UPDATE stock SET terminalid = $1, appversion = $2" + 
											" WHERE serialnumber = $3";
											pool.query(qry3, [tid, appversion, serial], (err, check) => {
												if (err) 
												{
													logger.error("Channels Profile Put Session Database Issue " + req.clientIp);
													res.status(500).send({"status": 500, "message": "Try Later"});
												}else
												{
													const termConfig = "SELECT * FROM terminalconfiguration where tid = $1 AND ifavailable = $2";
													pool.query(termConfig, [tid, "true"], (err,  config) => {    
														if(config.rows.length == 0)
														{
															obj.status = 200;
															obj.message = "Tid not profiled.";
															obj.errordata = null;
															res.header("Content-Type",'application/json').status(500).send(obj);
														}else
														{
															var tconfig = config.rows[0];
															obj.tid = config.rows[0].tid;
															obj.mid = config.rows[0].mid;
															obj.serialnumber = config.rows[0].serialnumber;
															obj.timestamp = getDateTimeSpec();
															obj.terminalmodel = config.rows[0].terminalmodel;
															obj.initapplicationversion = config.rows[0].initapplicationversion;
															obj.merchantname = config.rows[0].merchantname;
															obj.merchantaddress = config.rows[0].merchantaddress;
															obj.adminpin = config.rows[0].adminpin;
															obj.merchantpin = config.rows[0].merchantpin;
															obj.changepin = config.rows[0].changepin;
															obj.contactname = config.rows[0].contactname;
															obj.contactphone = config.rows[0].contactphone;
															obj.email = config.rows[0].email;
															obj.mcc = config.rows[0].mcc;
															obj.datecreated = config.rows[0].datecreated;
															obj.namecreated = config.rows[0].namecreated;
															obj.datemodified = config.rows[0].datemodified;
															obj.namemodified = config.rows[0].namemodified;
															obj.lga = config.rows[0].lga;
															obj.appname = config.rows[0].appname;
															obj.country = config.rows[0].country;
															obj.countrycode = config.rows[0].countrycode;
															obj.maker = config.rows[0].maker;
															obj.checker = config.rows[0].checker;
															obj.profilename = config.rows[0].profilename;
															obj.terminalmanufacturer = config.rows[0].terminalmanufacturer;
															obj.blocked = config.rows[0].blocked;
															obj.blockedpin = config.rows[0].blockedpin;
															obj.ownerusername = config.rows[0].ownerusername;
															obj.superagent = config.rows[0].superagent;
															obj.dialogheading = config.rows[0].dialogheading;
															obj.simserial = config.rows[0].simserial;
															obj.simnumber = config.rows[0].simnumber;
															obj.simname = config.rows[0].simname;
															obj.accountname = config.rows[0].accountname;
															obj.accountcode = config.rows[0].accountcode;
															obj.accountnumber = config.rows[0].accountnumber;
															obj.accountbank = config.rows[0].accountbank;
															obj.ifavailable = config.rows[0].ifavailable;
															obj.profileid = config.rows[0].profileid;
															obj.ownerusername = config.rows[0].ownerusername;
															
															obj.stampduty = config.rows[0].stampduty;
															obj.msc = config.rows[0].msc;
															obj.switchfee = config.rows[0].switchfee;
															obj.tmsfeerule = config.rows[0].tmsfeerule;
															obj.superagentfeerule = config.rows[0].superagentfeerule;
															obj.ctransferrule = config.rows[0].tmstransferrule;
															obj.satfeerule = config.rows[0].superagenttransferrule;
															obj.tmo = config.rows[0].tmo;
															obj.sanef = config.rows[0].sanefnumber;
															obj.percentagerule = config.rows[0].percentagerule;
															obj.maxamount = config.rows[0].maxamount;
															obj.hostswitchamount = config.rows[0].hostswitchamount;
															obj.superpercentage = config.rows[0].superpercentage;
															obj.currentversion = currentVersion;
															obj.forceallterminals = forceAllTerminals;

															obj.encmstkey = config.rows[0].encmstkey;
															obj.clrmstkey = config.rows[0].clrmstkey;
															obj.encseskey = config.rows[0].encseskey;
															obj.clrseskey = config.rows[0].clrseskey;
															obj.encpinkey = config.rows[0].encpinkey;
															obj.clrpinkey = config.rows[0].clrpinkey;
															obj.paramdownload = config.rows[0].paramdownload;
															


															//
															obj.iswtid = config.rows[0].iswtid;
															obj.iswmid = config.rows[0].iswmid;
															obj.wdcapped = config.rows[0].wdcapped;
															obj.wdsharesa = config.rows[0].wdsharesa;
															obj.wdsharess = config.rows[0].wdsharess;
															obj.cttms = config.rows[0].cttms;
															obj.ctsuperagent = config.rows[0].ctsuperagent;
															obj.ctsupersuperagent = config.rows[0].ctsupersuperagent;
															obj.wtsupersuper = config.rows[0].wtsupersuper;

															obj.riid = riid;
															obj.setbank = setbank;
															if(config.rows[0].tid === "2082OM54")
															{
																obj.riid = "627787";
																obj.setbank = "0520082938";
															}
															obj.agencyip = agencyip;
															obj.agencyport = agencyport;

															const appl =
																`SELECT * FROM terminalapplications WHERE brand = $1 AND model = $2`;
															pool.query(appl, [brand, model], (err,  applic) => {    
																if (err) 
																{
																	obj.status = 200;
																	obj.message = "Tid has terminalapplication issues. Contact Admin";
																	obj.data = tconfig;
																	return res.header("Content-Type",'application/json').status(500).send(obj);
																}else
																{
																	if(applic.rows.length < 1)
																	{
																		obj.appversion = null;
																		obj.appbrand = null;
																		obj.appdescription = null;
																		obj.appmodel = null;
																		obj.appfix = null;
																		obj.appterminals = null;
																		obj.appupdated = null;
																		obj.appremarks = null;
																	}
																	else
																	{
																		var ap = applic.rows;
																		for(var i = 0; i < ap.length; i++)
																		{
																			if (ap[i].terminals.indexOf("ALL " + brand + " TERMINALS") >= 0) 
																			{
																				obj.appversion = applic.rows[i].version;
																				obj.appbrand = applic.rows[i].brand;
																				obj.appdescription = applic.rows[i].description;
																				obj.appmodel = applic.rows[i].model;
																				obj.appfix = applic.rows[i].fix;
																				obj.appterminals = applic.rows[i].terminals;
																				obj.appupdated = applic.rows[i].updated;
																				obj.appremarks = applic.rows[i].remarks;
																				break;
																			} else if(ap[i].terminals.indexOf(tid) >= 0) 
																			{
																				obj.appversion = applic.rows[i].version;
																				obj.appbrand = applic.rows[i].brand;
																				obj.appdescription = applic.rows[i].description;
																				obj.appmodel = applic.rows[i].model;
																				obj.appfix = applic.rows[i].fix;
																				obj.appterminals = applic.rows[i].terminals;
																				obj.appupdated = applic.rows[i].updated;
																				obj.appremarks = applic.rows[i].remarks;
																				break;
																			}
																		}
																		if(appversion === obj.appversion)
																		{
																			obj.appversion = null;
																			obj.appbrand = null;
																			obj.appdescription = null;
																			obj.appmodel = null;
																			obj.appfix = null;
																			obj.appterminals = null;
																			obj.appupdated = null;
																			obj.appremarks = null;
																		}
																	}

																	const pro =
																		"SELECT * FROM profile WHERE id = $1 AND ifavailable = $2";
																	pool.query(pro, [obj.profileid, "true"], (err,  profile) => { 
																		if (err) 
																		{
																			obj.status = 200;
																			obj.message = "Tid has Profile issues. Contact Admin";
																			obj.errordata = null;
																			res.header("Content-Type",'application/json').status(500).send(obj);
																		}
																		else
																		{
																			if(profile.rows.length < 1)
																			{
																				obj.status = 200;
																				obj.message = "Tid has Profile issues. Contact Admin";
																				obj.errordata = null;
																				return res.header("Content-Type",'application/json').status(500).send(obj);
																			}
																			obj.profilename = profile.rows[0].name;
																			obj.profileremarks = profile.rows[0].remarks;
																			obj.profilecallhomeid = profile.rows[0].callhomeid;
																			obj.profilecommsid = profile.rows[0].commsid;
																			obj.profilereceiptid = profile.rows[0].receiptid;
																			obj.profilehostid = profile.rows[0].hostid;
																			obj.profileswitchkeyid = profile.rows[0].switchkeyid;
																			obj.profilecurrencyid = profile.rows[0].currencyid;
																			obj.profilebankid = profile.rows[0].bankid;
																			obj.profiletransactiontypesarray = profile.rows[0].transactiontypesarray;
																			obj.profilecardschemekeytypes = profile.rows[0].cardschemekeytypes;
																			obj.profilevas = profile.rows[0].vas;
																			obj.profileprotectlist = profile.rows[0].protectlist;
																			obj.profileotherimportant = profile.rows[0].otherimportant;
																			obj.profilehost2id = profile.rows[0].host2id;
																			obj.profilefswitchkeyid = profile.rows[0].fswitchkeyid;
																			obj.profilerlogoid = profile.rows[0].rlogoid;
																			obj.profileblogoid = profile.rows[0].blogoid;
																			obj.profilehostarray = profile.rows[0].hostarray;
																			obj.profiletmspay = profile.rows[0].tmspay;
																			
																			const ce =
																				"SELECT * FROM callhome WHERE id = $1";
																			pool.query(ce, [obj.profilecallhomeid], (err,  ch) => { 
																				if (err) 
																				{
																					obj.status = 200;
																					obj.message = "Tid has Profile issues. Contact Admin";
																					obj.errordata = null;
																					res.header("Content-Type",'application/json').status(500).send(obj);
																				}
																				else
																				{
																					if(ch.rows.length < 1)
																					{
																						obj.status = 200;
																						obj.message = "1x Tid has Callhome issues. Contact Admin";
																						obj.errordata = null;
																						return res.header("Content-Type",'application/json').status(500).send(obj);
																					}else
																					{
																						obj.chname = ch.rows[0].name;
																						obj.chinterval = ch.rows[0].interval;
																						obj.chip = ch.rows[0].ip;
																						obj.chport = ch.rows[0].port;
																						obj.chremotedownloadtime = ch.rows[0].remotedownloadtime;
																						obj.chcount = ch.rows[0].count;
																						
																						const cc =
																							"SELECT * FROM comms WHERE id = $1";
																						pool.query(cc, [obj.profilecommsid], (err,  com) => { 
																							if (err) 
																							{
																								obj.status = 200;
																								obj.message = "Tid has Profile issues. Contact Admin";
																								obj.errordata = null;
																								return res.header("Content-Type",'application/json').status(500).send(obj);
																							}
																							else
																							{
																								if(com.rows.length < 1)
																								{
																									obj.status = 200;
																									obj.message = "1ax Tid has Callhome issues. Contact Admin";
																									obj.errordata = null;
																									return res.header("Content-Type",'application/json').status(500).send(obj);
																								}else
																								{
																									obj.comname = com.rows[0].name;
																									obj.comusername = com.rows[0].username;
																									obj.comgateway = com.rows[0].gateway;
																									obj.comip = com.rows[0].ip;
																									obj.comport = com.rows[0].port;
																									obj.comapn = com.rows[0].apn;
																									obj.compassword = com.rows[0].password;
																									obj.comremarks = com.rows[0].remarks;
																									obj.comcommstype = com.rows[0].commstype;
																									obj.comipmode = com.rows[0].ipmode;
																									
																									const rp =
																										"SELECT * FROM receipt WHERE id = $1";
																									pool.query(rp, [obj.profilereceiptid], (err,  rpt) => { 
																										if (err) 
																										{
																											obj.status = 200;
																											obj.message = "Tid has Profile issues. Contact Admin";
																											obj.errordata = null;
																											res.header("Content-Type",'application/json').status(500).send(obj);
																										}
																										else
																										{
																											if(rpt.rows.length < 1)
																											{
																												obj.status = 200;
																												obj.message = "1ac Tid has Callhome issues. Contact Admin";
																												obj.errordata = null;
																												return res.header("Content-Type",'application/json').status(500).send(obj);
																											}else
																											{
																												obj.rptname = rpt.rows[0].name;
																												obj.rptfootertext = rpt.rows[0].footertext;
																												obj.rptcustomercopylabel = rpt.rows[0].customercopylabel;
																												obj.rptmerchantcopylabel = rpt.rows[0].merchantcopylabel;
																												obj.rptfootnotelabel = rpt.rows[0].footnotelabel;
																												obj.rptnormalfontsize = rpt.rows[0].normalfontsize;
																												obj.rptheaderfontsize = rpt.rows[0].headerfontsize;
																												obj.rptamountfontsize = rpt.rows[0].amountfontsize;
																												obj.rptprintmerchantcopynumber = rpt.rows[0].printmerchantcopynumber;
																												obj.rptprintclientcopynumber = rpt.rows[0].printclientcopynumber;
																												obj.rptshowlogo = rpt.rows[0].showlogo;
																												obj.rptshowbarcode = rpt.rows[0].showbarcode;
																												obj.rptsaveforreceipt = rpt.rows[0].saveforreceipt;

																												const hi =
																													"SELECT * FROM host WHERE id = $1";
																												pool.query(hi, [obj.profilehostid], (err,  hostid) => { 
																													if (err) 
																													{
																														obj.status = 200;
																														obj.message = "Tid has Profile issues. Contact Admin";
																														obj.errordata = null;
																														res.header("Content-Type",'application/json').status(500).send(obj);
																													}
																													else
																													{
																														if(hostid.rows.length < 1)
																														{
																															obj.status = 200;
																															obj.message = "1ad Tid has Callhome issues. Contact Admin";
																															obj.errordata = null;
																															return res.header("Content-Type",'application/json').status(500).send(obj);
																														}else
																														{
																															obj.hostidname = hostid.rows[0].name;
																															obj.hostip = hostid.rows[0].ip;
																															obj.hostport = hostid.rows[0].port;
																															obj.hostssl = hostid.rows[0].ssl;
																															obj.hostfriendlyname = hostid.rows[0].friendlyname;
																															obj.hostmestype = hostid.rows[0].mestype;

																															
																															const sk =
																																"SELECT * FROM keys WHERE id = $1";
																															pool.query(sk, [obj.profileswitchkeyid], (err,  swk) => { 
																																if (err) 
																																{
																																	obj.status = 200;
																																	obj.message = "Tid has Profile issues. Contact Admin";
																																	obj.errordata = null;
																																	res.header("Content-Type",'application/json').status(500).send(obj);
																																}
																																else
																																{
																																	if(swk.rows.length < 1)
																																	{
																																		obj.status = 200;
																																		obj.message = "1ae Tid has Callhome issues. Contact Admin";
																																		obj.errordata = null;
																																		return res.header("Content-Type",'application/json').status(500).send(obj);
																																	}else
																																	{
																																		obj.swkname = swk.rows[0].name;
																																		obj.swkcomponent1 = swk.rows[0].component1;
																																		obj.swkcomponent2 = swk.rows[0].component2;
																																		
																																		const cu =
																																			"SELECT * FROM currency WHERE id = $1";
																																		pool.query(cu, [obj.profilecurrencyid], (err,  cur) => { 
																																			if (err) 
																																			{
																																				obj.status = 200;
																																				obj.message = "Tid has Profile issues. Contact Admin";
																																				obj.errordata = null;
																																				res.header("Content-Type",'application/json').status(500).send(obj);
																																			}
																																			else
																																			{
																																				if(cur.rows.length < 1)
																																				{
																																					obj.status = 200;
																																					obj.message = "1af Tid has Callhome issues. Contact Admin";
																																					obj.errordata = null;
																																					return res.header("Content-Type",'application/json').status(500).send(obj);
																																				}else
																																				{
																																					obj.curname =  cur.rows[0].name;
																																					obj.curabbreviation =  cur.rows[0].abbreviation;
																																					obj.curcode =  cur.rows[0].code;
																																					obj.curminorunit =  cur.rows[0].minorunit;
																																					obj.curremarks =  cur.rows[0].remarks;
																																					
																																					const bn =
																																						"SELECT * FROM banks WHERE id = $1";
																																					pool.query(bn, [obj.profilebankid], (err,  bnk) => { 
																																						if (err) 
																																						{
																																							obj.status = 200;
																																							obj.message = "Tid has Profile issues. Contact Admin";
																																							obj.errordata = null;
																																							return res.header("Content-Type",'application/json').status(500).send(obj);
																																						}
																																						else
																																						{
																																							if(bnk.rows.length < 1)
																																							{
																																								obj.status = 200;
																																								obj.message = "1ag Tid has Callhome issues. Contact Admin";
																																								obj.errordata = null;
																																								return res.header("Content-Type",'application/json').status(500).send(obj);
																																							}else
																																							{
																																								obj.bnkname =  bnk.rows[0].name;
																																								obj.bnkcode =  bnk.rows[0].code;
																																								obj.bnkremarks =  bnk.rows[0].remarks;
																																								
																																								var tt = obj.profiletransactiontypesarray;
																																								var str = [];
																																								var init = "";
																																								for(var i = 0; i < tt.length; i++)
																																								{
																																									if(tt[i] === '#')
																																									{
																																										str.push(parseInt(init));
																																										init = "";
																																										continue;
																																									}else
																																									{
																																										init = init + tt[i];
																																										continue;
																																									}
																																								}
																																								
																																								if(str.length > 0)
																																								{
																																									var use = ""
																																									for(var j = 0; j < str.length; j++)
																																									{
																																										if(j == 0)
																																											use = " WHERE id = " + str[j]
																																										else
																																											use += " OR id = " + str[j]
																																									}
																																									var ttypes =
																																									"SELECT * FROM transactiontype " + use + " ORDER BY position ASC;";
																																									pool.query(ttypes, (err,  types) => {    
																																										if (err) 
																																										{
																																											obj.status = 200;
																																											obj.message = "Tid has transaction issues. Contact Admin";
																																											obj.errordata = tconfig;
																																											return res.header("Content-Type",'application/json').status(500).send(obj);
																																										}else
																																										{
																																											if(types.rows.length < 1)
																																											{
																																												obj.status = 200;
																																												obj.message = "Success. No Transaction Type";
																																												obj.data = tconfig;
																																												return res.header("Content-Type",'application/json').status(500).send(obj);
																																											}
																																											else
																																											{
																																												var txnarr = [];
																																												var txntxt = "";
																																												
																																												for(var i = 0; i < types.rows.length; i++)
																																												{
																																													txntxt += "name - " + types.rows[i].name;
																																													txntxt += "###common - " + types.rows[i].commonname;
																																													txntxt += "###transtype - " + types.rows[i].transtype;
																																													txntxt += "###uses - " + types.rows[i].uses
																																													txntxt += "###position - " + types.rows[i].position
																																													txntxt += "###discountpercent - " + types.rows[i].discountpercent
																																													txntxt += "###discount - " + types.rows[i].discount
																																													txntxt += "###commissionpercent - " + types.rows[i].commissionpercent
																																													txntxt += "###commission - " + types.rows[i].commission
																																													txntxt += "###baseamtpercentage - " + types.rows[i].baseamtpercentage
																																													txntxt += "###baseamtfixed - " + types.rows[i].baseamtfixed
																																													txntxt += "###remarks - " + types.rows[i].remarks
																																													txnarr.push(txntxt);
																																													txntxt = "";
																																												}
																																												
																																												obj.transactions = txnarr.toString();
																																												
																																												var ha = obj.profilehostarray;
																																												var arry3 = [];
																																												var arry4 = [];
																																												var ar3 = "";
																																												var ar4 = "";
																																												var loop = 0;
																																												if(ha)
																																												{
																																													for(var j = 0; j < ha.length; j++)
																																													{
																																														if(ha.charAt(j) === '#')
																																														{
																																															loop = 0;
																																															arry4.push(ar4);
																																															ar4 = "";
																																														}else if(ha.charAt(j) === ' ')
																																														{
																																															loop = 1;
																																															arry3.push(parseInt(ar3));
																																															ar3 = "";
																																															j += 2;
																																														}else
																																														{
																																															if(loop === 0)
																																															{
																																																ar3 += ha.charAt(j);
																																															}else
																																															{
																																																ar4 += ha.charAt(j);
																																															}
																																														}
																																													}
																																												}

																																												const tta =
																																													`SELECT name, position FROM transactiontype ORDER BY position ASC`;
																																												pool.query(tta, (err,  ttar) => {    
																																													if (err) 
																																													{
																																														console.log(err);
																																														obj.status = 200;
																																														obj.message = "Success. Transaction Host Error";
																																														obj.data = tconfig;
																																														return res.header("Content-Type",'application/json').status(500).send(obj);
																																													}
																																													else
																																													{
																																														var harr2 = [];
																																														var htxt2 = "";
																																														var ejo = ttar.rows;
																																														for(var j = 0; j < ejo.length; j++) 
																																														{
																																															var ch = ejo[j].id;
																																															var k = arry3.indexOf(ch);
																																															
																																															if(arry4[k] === 'h2')
																																															{
																																																htxt2 += ejo[j].name;
																																																htxt2 += "###host2###"
																																																harr2.push(htxt2);
																																																htxt2 = "";
																																															}else
																																															{
																																																htxt2 += ejo[j].name;
																																																htxt2 += "###host1###"
																																																harr2.push(htxt2);
																																																htxt2 = "";
																																															}
																																														}
																																														obj.hostarray = harr2.toString();

																																														
																																														var zz = obj.profileprotectlist;
																																														var str2 = [];
																																														var init2 = "";
																																														if(zz !== null)
																																														{
																																															for(var i = 0; i < zz.length; i++)
																																															{
																																																if(zz[i] === '#')
																																																{
																																																	str2.push(parseInt(init2));
																																																	init2 = "";
																																																	continue;
																																																}else
																																																{
																																																	init2 = init2 + zz[i];
																																																	continue;
																																																}
																																															}
																																														}
																																														
																																														
																																														if(str2.length > 0)
																																														{
																																															var use = ""
																																															for(var j = 0; j < str2.length; j++)
																																															{
																																																if(j == 0)
																																																	use = " WHERE id = " + str2[j]
																																																else
																																																	use += " OR id = " + str2[j]
																																															}
																																															var ttypes2 =
																																																	"SELECT name FROM transactiontype " + use + ";";
																																															pool.query(ttypes2, (err,  types2) => { 
																																																if (err) 
																																																{
																																																	obj.status = 200;
																																																	obj.message = "Success. Transaction Type Error";
																																																	obj.data = tconfig;
																																																	return res.header("Content-Type",'application/json').status(500).send(obj);
																																																}
																																																else
																																																{
																																																	if(types2.rows.length > 0)
																																																	{
																																																		var txnarr2 = [];
																																																		var txntxt2 = "";
																																																		
																																																		for(var i = 0; i < types2.rows.length; i++)
																																																		{
																																																			txntxt2 += "name - " + types2.rows[i].name;
																																																			txntxt2 += "###"
																																																			txnarr2.push(txntxt2);
																																																			txntxt2 = "";
																																																		}
																																																		obj.protectlist = txnarr2.toString();

																																																		
																																																		const h2 =
																																																			"SELECT * FROM host WHERE id = $1";
																																																		pool.query(h2, [obj.profilehost2id], (err,  hostid2) => { 
																																																			if (err) 
																																																			{
																																																				obj.status = 200;
																																																				obj.message = "Tid has Profile issues. Contact Admin";
																																																				obj.errordata = null;
																																																				res.header("Content-Type",'application/json').status(500).send(obj);
																																																			}
																																																			else
																																																			{
																																																				if(hostid2.rows.length < 1)
																																																				{
																																																					obj.status = 200;
																																																					obj.message = "iap Tid has Callhome issues. Contact Admin";
																																																					obj.errordata = null;
																																																					return res.header("Content-Type",'application/json').status(500).send(obj);
																																																				}else
																																																				{
																																																					obj.hostid2name = hostid2.rows[0].name;
																																																					obj.host2ip = hostid2.rows[0].ip;
																																																					obj.host2port = hostid2.rows[0].port;
																																																					obj.host2ssl = hostid2.rows[0].ssl;
																																																					obj.host2friendlyname = hostid2.rows[0].friendlyname;
																																																					obj.host2mestype = hostid2.rows[0].mestype;
																																																					
																																																					const sk2 =
																																																						"SELECT * FROM keys WHERE id = $1";
																																																					pool.query(sk2, [obj.profilefswitchkeyid], (err,  swk2) => { 
																																																						if (err) 
																																																						{
																																																							obj.status = 200;
																																																							obj.message = "Tid has Profile issues. Contact Admin";
																																																							obj.errordata = null;
																																																							res.header("Content-Type",'application/json').status(500).send(obj);
																																																						}
																																																						else
																																																						{
																																																							if(swk2.rows.length < 1)
																																																							{
																																																								obj.status = 200;
																																																								obj.message = "1am Tid has Callhome issues. Contact Admin";
																																																								obj.errordata = null;
																																																								return res.header("Content-Type",'application/json').status(500).send(obj);
																																																							}else
																																																							{
																																																								obj.swk2name = swk2.rows[0].name;
																																																								obj.swk2component1 = swk2.rows[0].component1;
																																																								obj.swk2component2 = swk2.rows[0].component2;
																																																								
																																																								if(obj.profilerlogoid !== "0")
																																																								{
																																																									const lg =
																																																										"SELECT * FROM logos WHERE id = $1";
																																																									pool.query(lg, [obj.profilerlogoid], (err,  logo) => { 
																																																										if (err) 
																																																										{
																																																											obj.status = 200;
																																																											obj.message = "Tid has Logo issues. Contact Admin";
																																																											obj.errordata = null;
																																																											res.header("Content-Type",'application/json').status(500).send(obj);
																																																										}
																																																										else
																																																										{
																																																											if(logo.rows.length < 1)
																																																											{
																																																												obj.status = 200;
																																																												obj.message = "1an Tid has Callhome issues. Contact Admin";
																																																												obj.errordata = null;
																																																												return res.header("Content-Type",'application/json').status(500).send(obj);
																																																											}else
																																																											{
																																																												obj.logorversion =  logo.rows[0].version;
																																																												obj.logorfilename =  logo.rows[0].filename;
																																																												obj.logordescription =  logo.rows[0].description;
																																																												obj.logorbankname =  logo.rows[0].bankname;
																																																												obj.logorbankcode =  logo.rows[0].bankcode;
																																																												obj.logordownload =  logo.rows[0].download;
																																																												obj.logorisreceipt =  logo.rows[0].isreceipt;
																																																												
																																																												
																																																												if(obj.profileblogoid !== "0")
																																																												{
																																																													const lg =
																																																														"SELECT * FROM logos WHERE id = $1";
																																																													pool.query(lg, [obj.profileblogoid], (err,  logo) => { 
																																																														if (err) 
																																																														{
																																																															obj.status = 200;
																																																															obj.message = "Tid has Logo issues. Contact Admin";
																																																															obj.errordata = null;
																																																															res.header("Content-Type",'application/json').status(500).send(obj);
																																																														}
																																																														else
																																																														{
																																																															if(logo.rows.length < 1)
																																																															{
																																																																obj.status = 200;
																																																																obj.message = "Tid has Callhome issues. Contact Admin";
																																																																obj.errordata = null;
																																																																return res.header("Content-Type",'application/json').status(500).send(obj);
																																																															}else
																																																															{
																																																																obj.logobversion =  logo.rows[0].version;
																																																																obj.logobfilename =  logo.rows[0].filename;
																																																																obj.logobdescription =  logo.rows[0].description;
																																																																obj.logobbankname =  logo.rows[0].bankname;
																																																																obj.logobbankcode =  logo.rows[0].bankcode;
																																																																obj.logobdownload =  logo.rows[0].download;
																																																																obj.logobisreceipt =  logo.rows[0].isreceipt;
																																																																
																																																																obj.status = 200;
																																																																obj.message = "Success";
																																																																return res.header("Content-Type",'application/json').status(200).send(obj);
																																																																
																																																															}
																																																														}
																																																													});
																																																												}else
																																																												{
																																																													obj.status = 200;
																																																													obj.message = "Success";
																																																													return res.header("Content-Type",'application/json').status(200).send(obj);
																																																												}
																																																											}
																																																										}
																																																									});
																																																								}else
																																																								{
																																																									obj.status = 200;
																																																									obj.message = "Success";
																																																									return res.header("Content-Type",'application/json').status(200).send(obj);
																																																								}
																																																								
																																																							}
																																																						}
																																																					});
																																																					
																																																				}
																																																			}
																																																		});


																																																	}
																																																}
																																															});
																																														}else
																																														{
																																															obj.status = 200;
																																															obj.message = "Tid has protectlist issues. Contact Admin";
																																															obj.errordata = tconfig;
																																															return res.header("Content-Type",'application/json').status(500).send(obj);
																																														}	
																																													}
																																												});	
																																											}
																																										}
																																									});
																																									
																																								}else
																																								{
																																									obj.status = 200;
																																									obj.message = "Tid has transaction issues. Contact Admin";
																																									obj.errordata = tconfig;
																																									return res.header("Content-Type",'application/json').status(500).send(obj);
																																								}
																																								
																																							}
																																						}
																																					});
																																					
																																				}
																																			}
																																		});
																																	}
																																}
																															});
																														}
																													}
																												});	
																											}
																										}
																									});
																								}
																							}
																						});
																					}
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
							}
						});
                    }
                }
            }
		});
    }catch(e)
    {
        logger.error("Profile Download from: " + req.clientIp + ". Error Occurred ");
        res.header("Content-Type",'application/json').status(500).send({});
    }
});

router.get("/tempprofile", function(req, res)
{
    try
    {
		var brand = req.headers.brand;
		var model = req.headers.model;
		var serial = req.headers.serial;
		var appversion = req.headers.appversion;
		var token = req.headers.token;

		logger.info("BRAND: " + brand);
		logger.info("MODEL: " + model);
		logger.info("SERIAL: " + serial);
		logger.info("SERIAL LENGTH: " + serial.length);
		logger.info("APPVERSION: " + appversion);
		logger.info("Token: " + token);
		
		var qry = "SELECT * FROM tokens WHERE token = $1 AND username = $2";
        pool.query(qry, [token, serial], (err, lol) => {
            if (err) 
            {
                logger.info("tms TOKEN CHECK FAILED FOR " + req.clientIp);
                return res.status(500).send({"status": 500, "message": "An Error Occurred. Not Successful."});
            }else
            {
                if(lol.rows === undefined || lol.rows.length !== 1)
                {
                    logger.info("Kindly login again " + req.clientIp);
                    return res.status(500).send({"status": 500, "message": "Unauthorized"});
                }else
                {
                    var date1 = new Date();
                    var date2 = new Date(lol.rows[0].timestop);
                    var timeDiff = date1.getTime() - date2.getTime();
                    var dif = timeDiff / 1000;
                    if(dif >= 1)
                    {
                        logger.info("Time out. Please login again. " + req.clientIp);
                        return res.status(500).send({"status": 500, "message": "Time Out. Please Login."});
                    }else
                    {
                        var obj = new Object();
						obj.timestamp = getDateTimeSpec();
						logger.info("Profile Download Request From: Ip: " + req.clientIp);
						const termConfig = "SELECT * FROM stock where serialnumber = $1";
						pool.query(termConfig, [serial], (err,  ddd) => {    
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
								if(serial === 'nelsonulonna@gmail.com' ||
									serial === 'ogunkoyaseyefunmi@gmail.com' ||
									serial === 'obileyetemitope4@gmail.com' ||
									serial === 'temmyfree2rhyme@gmail.com' ||
									serial === 'inyassjamiu@gmail.com' ||
									serial === 'mercyblis@gmail.com' ||
									serial === 'ekeka500@gmail.com' ||
									serial === 'gloryoboh34@gmail.com' ||
									serial === 'ajibolajbl07@gmail.com'
									)
								{
									console.log("OUTSTANDING DEBT");
									return res.status(500).send({"status": 500, "message": "Outstanding Debt."});
								}else if(ddd.rows.length == 0)
								{
									obj.status = 200;
									obj.message = "Serial Number not recognized.";
									obj.errordata = null;
									res.header("Content-Type",'application/json').status(500).send(obj);
								}else
								{
									var tid = ddd.rows[0].terminalid;
									const query5 =
											"UPDATE terminalconfiguration SET terminalmanufacturer = $1, terminalmodel = $2, serialnumber = $3," + 
											"initapplicationversion = $4 WHERE tid = $5";
									pool.query(query5, [brand, model, serial, appversion, tid], (err,  r) => 
									{    
										if (err) 
										{
											obj.status = 200;
											obj.message = "Tid has issues. Contact Admin";
											obj.errordata = null;
											res.header("Content-Type",'application/json').status(500).send(obj);
										}
										else
										{
											var qry3 =
											"UPDATE stock SET terminalid = $1, appversion = $2" + 
											" WHERE serialnumber = $3";
											pool.query(qry3, [tid, appversion, serial], (err, check) => {
												if (err) 
												{
													logger.error("Channels Profile Put Session Database Issue " + req.clientIp);
													res.status(500).send({"status": 500, "message": "Try Later"});
												}else
												{
													const termConfig = "SELECT * FROM terminalconfiguration where tid = $1 AND ifavailable = $2";
													pool.query(termConfig, [tid, "true"], (err,  config) => {    
														if(config.rows.length == 0)
														{
															obj.status = 200;
															obj.message = "Tid not profiled.";
															obj.errordata = null;
															res.header("Content-Type",'application/json').status(500).send(obj);
														}else
														{
															var tconfig = config.rows[0];
															obj.tid = config.rows[0].tid;
															obj.mid = config.rows[0].mid;
															obj.serialnumber = config.rows[0].serialnumber;
															obj.timestamp = getDateTimeSpec();
															obj.terminalmodel = config.rows[0].terminalmodel;
															obj.initapplicationversion = config.rows[0].initapplicationversion;
															obj.merchantname = config.rows[0].merchantname;
															obj.merchantaddress = config.rows[0].merchantaddress;
															obj.adminpin = config.rows[0].adminpin;
															obj.merchantpin = config.rows[0].merchantpin;
															obj.changepin = config.rows[0].changepin;
															obj.contactname = config.rows[0].contactname;
															obj.contactphone = config.rows[0].contactphone;
															obj.email = config.rows[0].email;
															obj.mcc = config.rows[0].mcc;
															obj.datecreated = config.rows[0].datecreated;
															obj.namecreated = config.rows[0].namecreated;
															obj.datemodified = config.rows[0].datemodified;
															obj.namemodified = config.rows[0].namemodified;
															obj.lga = config.rows[0].lga;
															obj.appname = config.rows[0].appname;
															obj.country = config.rows[0].country;
															obj.countrycode = config.rows[0].countrycode;
															obj.maker = config.rows[0].maker;
															obj.checker = config.rows[0].checker;
															obj.profilename = config.rows[0].profilename;
															obj.terminalmanufacturer = config.rows[0].terminalmanufacturer;
															obj.blocked = config.rows[0].blocked;
															obj.blockedpin = config.rows[0].blockedpin;
															obj.ownerusername = config.rows[0].ownerusername;
															obj.superagent = config.rows[0].superagent;
															obj.dialogheading = config.rows[0].dialogheading;
															obj.simserial = config.rows[0].simserial;
															obj.simnumber = config.rows[0].simnumber;
															obj.simname = config.rows[0].simname;
															obj.accountname = config.rows[0].accountname;
															obj.accountcode = config.rows[0].accountcode;
															obj.accountnumber = config.rows[0].accountnumber;
															obj.accountbank = config.rows[0].accountbank;
															obj.ifavailable = config.rows[0].ifavailable;
															obj.profileid = config.rows[0].profileid;
															obj.ownerusername = config.rows[0].ownerusername;
															
															obj.stampduty = config.rows[0].stampduty;
															obj.msc = config.rows[0].msc;
															obj.switchfee = config.rows[0].switchfee;
															obj.tmsfeerule = config.rows[0].tmsfeerule;
															obj.superagentfeerule = config.rows[0].superagentfeerule;
															obj.ctransferrule = config.rows[0].tmstransferrule;
															obj.satfeerule = config.rows[0].superagenttransferrule;
															obj.tmo = config.rows[0].tmo;
															obj.sanef = config.rows[0].sanefnumber;
															obj.percentagerule = config.rows[0].percentagerule;
															obj.maxamount = config.rows[0].maxamount;
															obj.hostswitchamount = config.rows[0].hostswitchamount;
															obj.superpercentage = config.rows[0].superpercentage;
															obj.currentversion = currentVersion;
															obj.forceallterminals = forceAllTerminals;
															obj.encmstkey = config.rows[0].encmstkey;
															obj.clrmstkey = config.rows[0].clrmstkey;
															obj.encseskey = config.rows[0].encseskey;
															obj.clrseskey = config.rows[0].clrseskey;
															obj.encpinkey = config.rows[0].encpinkey;
															obj.clrpinkey = config.rows[0].clrpinkey;
															obj.paramdownload = config.rows[0].paramdownload;
															


															//
															obj.iswtid = config.rows[0].iswtid;
															obj.iswmid = config.rows[0].iswmid;
															obj.wdcapped = config.rows[0].wdcapped;
															obj.wdsharesa = config.rows[0].wdsharesa;
															obj.wdsharess = config.rows[0].wdsharess;
															obj.cttms = config.rows[0].cttms;
															obj.ctsuperagent = config.rows[0].ctsuperagent;
															obj.ctsupersuperagent = config.rows[0].ctsupersuperagent;
															obj.wtsupersuper = config.rows[0].wtsupersuper;

															obj.riid = riid;
															obj.setbank = setbank;
															if(config.rows[0].tid === "2082OM54")
															{
																obj.riid = "627787";
																obj.setbank = "0520082938";
															}
															obj.agencyip = agencyip;
															obj.agencyport = agencyport;

															const appl =
																`SELECT * FROM terminalapplications WHERE brand = $1 AND model = $2`;
															pool.query(appl, [brand, model], (err,  applic) => {    
																if (err) 
																{
																	obj.status = 200;
																	obj.message = "Tid has terminalapplication issues. Contact Admin";
																	obj.data = tconfig;
																	return res.header("Content-Type",'application/json').status(500).send(obj);
																}else
																{
																	if(applic.rows.length < 1)
																	{
																		obj.appversion = null;
																		obj.appbrand = null;
																		obj.appdescription = null;
																		obj.appmodel = null;
																		obj.appfix = null;
																		obj.appterminals = null;
																		obj.appupdated = null;
																		obj.appremarks = null;
																	}
																	else
																	{
																		var ap = applic.rows;
																		for(var i = 0; i < ap.length; i++)
																		{
																			if (ap[i].terminals.indexOf("ALL " + brand + " TERMINALS") >= 0) 
																			{
																				obj.appversion = applic.rows[i].version;
																				obj.appbrand = applic.rows[i].brand;
																				obj.appdescription = applic.rows[i].description;
																				obj.appmodel = applic.rows[i].model;
																				obj.appfix = applic.rows[i].fix;
																				obj.appterminals = applic.rows[i].terminals;
																				obj.appupdated = applic.rows[i].updated;
																				obj.appremarks = applic.rows[i].remarks;
																				break;
																			} else if(ap[i].terminals.indexOf(tid) >= 0) 
																			{
																				obj.appversion = applic.rows[i].version;
																				obj.appbrand = applic.rows[i].brand;
																				obj.appdescription = applic.rows[i].description;
																				obj.appmodel = applic.rows[i].model;
																				obj.appfix = applic.rows[i].fix;
																				obj.appterminals = applic.rows[i].terminals;
																				obj.appupdated = applic.rows[i].updated;
																				obj.appremarks = applic.rows[i].remarks;
																				break;
																			}
																		}
																		if(appversion === obj.appversion)
																		{
																			obj.appversion = null;
																			obj.appbrand = null;
																			obj.appdescription = null;
																			obj.appmodel = null;
																			obj.appfix = null;
																			obj.appterminals = null;
																			obj.appupdated = null;
																			obj.appremarks = null;
																		}
																	}

																	const pro =
																		"SELECT * FROM profile WHERE id = $1 AND ifavailable = $2";
																	pool.query(pro, [obj.profileid, "true"], (err,  profile) => { 
																		if (err) 
																		{
																			obj.status = 200;
																			obj.message = "Tid has Profile issues. Contact Admin";
																			obj.errordata = null;
																			res.header("Content-Type",'application/json').status(500).send(obj);
																		}
																		else
																		{
																			if(profile.rows.length < 1)
																			{
																				obj.status = 200;
																				obj.message = "Tid has Profile issues. Contact Admin";
																				obj.errordata = null;
																				return res.header("Content-Type",'application/json').status(500).send(obj);
																			}
																			obj.profilename = profile.rows[0].name;
																			obj.profileremarks = profile.rows[0].remarks;
																			obj.profilecallhomeid = profile.rows[0].callhomeid;
																			obj.profilecommsid = profile.rows[0].commsid;
																			obj.profilereceiptid = profile.rows[0].receiptid;
																			obj.profilehostid = profile.rows[0].hostid;
																			obj.profileswitchkeyid = profile.rows[0].switchkeyid;
																			obj.profilecurrencyid = profile.rows[0].currencyid;
																			obj.profilebankid = profile.rows[0].bankid;
																			obj.profiletransactiontypesarray = profile.rows[0].transactiontypesarray;
																			obj.profilecardschemekeytypes = profile.rows[0].cardschemekeytypes;
																			obj.profilevas = profile.rows[0].vas;
																			obj.profileprotectlist = profile.rows[0].protectlist;
																			obj.profileotherimportant = profile.rows[0].otherimportant;
																			obj.profilehost2id = profile.rows[0].host2id;
																			obj.profilefswitchkeyid = profile.rows[0].fswitchkeyid;
																			obj.profilerlogoid = profile.rows[0].rlogoid;
																			obj.profileblogoid = profile.rows[0].blogoid;
																			obj.profilehostarray = profile.rows[0].hostarray;
																			obj.profiletmspay = profile.rows[0].tmspay;
																			
																			const ce =
																				"SELECT * FROM callhome WHERE id = $1";
																			pool.query(ce, [obj.profilecallhomeid], (err,  ch) => { 
																				if (err) 
																				{
																					obj.status = 200;
																					obj.message = "Tid has Profile issues. Contact Admin";
																					obj.errordata = null;
																					res.header("Content-Type",'application/json').status(500).send(obj);
																				}
																				else
																				{
																					if(ch.rows.length < 1)
																					{
																						obj.status = 200;
																						obj.message = "1x Tid has Callhome issues. Contact Admin";
																						obj.errordata = null;
																						return res.header("Content-Type",'application/json').status(500).send(obj);
																					}else
																					{
																						obj.chname = ch.rows[0].name;
																						obj.chinterval = ch.rows[0].interval;
																						obj.chip = ch.rows[0].ip;
																						obj.chport = ch.rows[0].port;
																						obj.chremotedownloadtime = ch.rows[0].remotedownloadtime;
																						obj.chcount = ch.rows[0].count;
																						
																						const cc =
																							"SELECT * FROM comms WHERE id = $1";
																						pool.query(cc, [obj.profilecommsid], (err,  com) => { 
																							if (err) 
																							{
																								obj.status = 200;
																								obj.message = "Tid has Profile issues. Contact Admin";
																								obj.errordata = null;
																								return res.header("Content-Type",'application/json').status(500).send(obj);
																							}
																							else
																							{
																								if(com.rows.length < 1)
																								{
																									obj.status = 200;
																									obj.message = "1ax Tid has Callhome issues. Contact Admin";
																									obj.errordata = null;
																									return res.header("Content-Type",'application/json').status(500).send(obj);
																								}else
																								{
																									obj.comname = com.rows[0].name;
																									obj.comusername = com.rows[0].username;
																									obj.comgateway = com.rows[0].gateway;
																									obj.comip = com.rows[0].ip;
																									obj.comport = com.rows[0].port;
																									obj.comapn = com.rows[0].apn;
																									obj.compassword = com.rows[0].password;
																									obj.comremarks = com.rows[0].remarks;
																									obj.comcommstype = com.rows[0].commstype;
																									obj.comipmode = com.rows[0].ipmode;
																									
																									const rp =
																										"SELECT * FROM receipt WHERE id = $1";
																									pool.query(rp, [obj.profilereceiptid], (err,  rpt) => { 
																										if (err) 
																										{
																											obj.status = 200;
																											obj.message = "Tid has Profile issues. Contact Admin";
																											obj.errordata = null;
																											res.header("Content-Type",'application/json').status(500).send(obj);
																										}
																										else
																										{
																											if(rpt.rows.length < 1)
																											{
																												obj.status = 200;
																												obj.message = "1ac Tid has Callhome issues. Contact Admin";
																												obj.errordata = null;
																												return res.header("Content-Type",'application/json').status(500).send(obj);
																											}else
																											{
																												obj.rptname = rpt.rows[0].name;
																												obj.rptfootertext = rpt.rows[0].footertext;
																												obj.rptcustomercopylabel = rpt.rows[0].customercopylabel;
																												obj.rptmerchantcopylabel = rpt.rows[0].merchantcopylabel;
																												obj.rptfootnotelabel = rpt.rows[0].footnotelabel;
																												obj.rptnormalfontsize = rpt.rows[0].normalfontsize;
																												obj.rptheaderfontsize = rpt.rows[0].headerfontsize;
																												obj.rptamountfontsize = rpt.rows[0].amountfontsize;
																												obj.rptprintmerchantcopynumber = rpt.rows[0].printmerchantcopynumber;
																												obj.rptprintclientcopynumber = rpt.rows[0].printclientcopynumber;
																												obj.rptshowlogo = rpt.rows[0].showlogo;
																												obj.rptshowbarcode = rpt.rows[0].showbarcode;
																												obj.rptsaveforreceipt = rpt.rows[0].saveforreceipt;

																												const hi =
																													"SELECT * FROM host WHERE id = $1";
																												pool.query(hi, [obj.profilehostid], (err,  hostid) => { 
																													if (err) 
																													{
																														obj.status = 200;
																														obj.message = "Tid has Profile issues. Contact Admin";
																														obj.errordata = null;
																														res.header("Content-Type",'application/json').status(500).send(obj);
																													}
																													else
																													{
																														if(hostid.rows.length < 1)
																														{
																															obj.status = 200;
																															obj.message = "1ad Tid has Callhome issues. Contact Admin";
																															obj.errordata = null;
																															return res.header("Content-Type",'application/json').status(500).send(obj);
																														}else
																														{
																															obj.hostidname = hostid.rows[0].name;
																															obj.hostip = hostid.rows[0].ip;
																															obj.hostport = hostid.rows[0].port;
																															obj.hostssl = hostid.rows[0].ssl;
																															obj.hostfriendlyname = hostid.rows[0].friendlyname;
																															obj.hostmestype = hostid.rows[0].mestype;

																															
																															const sk =
																																"SELECT * FROM keys WHERE id = $1";
																															pool.query(sk, [obj.profileswitchkeyid], (err,  swk) => { 
																																if (err) 
																																{
																																	obj.status = 200;
																																	obj.message = "Tid has Profile issues. Contact Admin";
																																	obj.errordata = null;
																																	res.header("Content-Type",'application/json').status(500).send(obj);
																																}
																																else
																																{
																																	if(swk.rows.length < 1)
																																	{
																																		obj.status = 200;
																																		obj.message = "1ae Tid has Callhome issues. Contact Admin";
																																		obj.errordata = null;
																																		return res.header("Content-Type",'application/json').status(500).send(obj);
																																	}else
																																	{
																																		obj.swkname = swk.rows[0].name;
																																		obj.swkcomponent1 = swk.rows[0].component1;
																																		obj.swkcomponent2 = swk.rows[0].component2;
																																		
																																		const cu =
																																			"SELECT * FROM currency WHERE id = $1";
																																		pool.query(cu, [obj.profilecurrencyid], (err,  cur) => { 
																																			if (err) 
																																			{
																																				obj.status = 200;
																																				obj.message = "Tid has Profile issues. Contact Admin";
																																				obj.errordata = null;
																																				res.header("Content-Type",'application/json').status(500).send(obj);
																																			}
																																			else
																																			{
																																				if(cur.rows.length < 1)
																																				{
																																					obj.status = 200;
																																					obj.message = "1af Tid has Callhome issues. Contact Admin";
																																					obj.errordata = null;
																																					return res.header("Content-Type",'application/json').status(500).send(obj);
																																				}else
																																				{
																																					obj.curname =  cur.rows[0].name;
																																					obj.curabbreviation =  cur.rows[0].abbreviation;
																																					obj.curcode =  cur.rows[0].code;
																																					obj.curminorunit =  cur.rows[0].minorunit;
																																					obj.curremarks =  cur.rows[0].remarks;
																																					
																																					const bn =
																																						"SELECT * FROM banks WHERE id = $1";
																																					pool.query(bn, [obj.profilebankid], (err,  bnk) => { 
																																						if (err) 
																																						{
																																							obj.status = 200;
																																							obj.message = "Tid has Profile issues. Contact Admin";
																																							obj.errordata = null;
																																							return res.header("Content-Type",'application/json').status(500).send(obj);
																																						}
																																						else
																																						{
																																							if(bnk.rows.length < 1)
																																							{
																																								obj.status = 200;
																																								obj.message = "1ag Tid has Callhome issues. Contact Admin";
																																								obj.errordata = null;
																																								return res.header("Content-Type",'application/json').status(500).send(obj);
																																							}else
																																							{
																																								obj.bnkname =  bnk.rows[0].name;
																																								obj.bnkcode =  bnk.rows[0].code;
																																								obj.bnkremarks =  bnk.rows[0].remarks;
																																								
																																								var tt = obj.profiletransactiontypesarray;
																																								var str = [];
																																								var init = "";
																																								for(var i = 0; i < tt.length; i++)
																																								{
																																									if(tt[i] === '#')
																																									{
																																										str.push(parseInt(init));
																																										init = "";
																																										continue;
																																									}else
																																									{
																																										init = init + tt[i];
																																										continue;
																																									}
																																								}
																																								
																																								if(str.length > 0)
																																								{
																																									var use = ""
																																									for(var j = 0; j < str.length; j++)
																																									{
																																										if(j == 0)
																																											use = " WHERE id = " + str[j]
																																										else
																																											use += " OR id = " + str[j]
																																									}
																																									var ttypes =
																																									"SELECT * FROM transactiontype " + use + " ORDER BY position ASC;";
																																									pool.query(ttypes, (err,  types) => {    
																																										if (err) 
																																										{
																																											obj.status = 200;
																																											obj.message = "Tid has transaction issues. Contact Admin";
																																											obj.errordata = tconfig;
																																											return res.header("Content-Type",'application/json').status(500).send(obj);
																																										}else
																																										{
																																											if(types.rows.length < 1)
																																											{
																																												obj.status = 200;
																																												obj.message = "Success. No Transaction Type";
																																												obj.data = tconfig;
																																												return res.header("Content-Type",'application/json').status(500).send(obj);
																																											}
																																											else
																																											{
																																												var txnarr = [];
																																												var txntxt = "";
																																												
																																												for(var i = 0; i < types.rows.length; i++)
																																												{
																																													txntxt += "name - " + types.rows[i].name;
																																													txntxt += "###common - " + types.rows[i].commonname;
																																													txntxt += "###transtype - " + types.rows[i].transtype;
																																													txntxt += "###uses - " + types.rows[i].uses
																																													txntxt += "###position - " + types.rows[i].position
																																													txntxt += "###discountpercent - " + types.rows[i].discountpercent
																																													txntxt += "###discount - " + types.rows[i].discount
																																													txntxt += "###commissionpercent - " + types.rows[i].commissionpercent
																																													txntxt += "###commission - " + types.rows[i].commission
																																													txntxt += "###baseamtpercentage - " + types.rows[i].baseamtpercentage
																																													txntxt += "###baseamtfixed - " + types.rows[i].baseamtfixed
																																													txntxt += "###remarks - " + types.rows[i].remarks
																																													txnarr.push(txntxt);
																																													txntxt = "";
																																												}
																																												
																																												obj.transactions = txnarr.toString();
																																												
																																												var ha = obj.profilehostarray;
																																												var arry3 = [];
																																												var arry4 = [];
																																												var ar3 = "";
																																												var ar4 = "";
																																												var loop = 0;
																																												if(ha)
																																												{
																																													for(var j = 0; j < ha.length; j++)
																																													{
																																														if(ha.charAt(j) === '#')
																																														{
																																															loop = 0;
																																															arry4.push(ar4);
																																															ar4 = "";
																																														}else if(ha.charAt(j) === ' ')
																																														{
																																															loop = 1;
																																															arry3.push(parseInt(ar3));
																																															ar3 = "";
																																															j += 2;
																																														}else
																																														{
																																															if(loop === 0)
																																															{
																																																ar3 += ha.charAt(j);
																																															}else
																																															{
																																																ar4 += ha.charAt(j);
																																															}
																																														}
																																													}
																																												}

																																												const tta =
																																													`SELECT name, position FROM transactiontype ORDER BY position ASC`;
																																												pool.query(tta, (err,  ttar) => {    
																																													if (err) 
																																													{
																																														console.log(err);
																																														obj.status = 200;
																																														obj.message = "Success. Transaction Host Error";
																																														obj.data = tconfig;
																																														return res.header("Content-Type",'application/json').status(500).send(obj);
																																													}
																																													else
																																													{
																																														var harr2 = [];
																																														var htxt2 = "";
																																														var ejo = ttar.rows;
																																														for(var j = 0; j < ejo.length; j++) 
																																														{
																																															var ch = ejo[j].id;
																																															var k = arry3.indexOf(ch);
																																															
																																															if(arry4[k] === 'h2')
																																															{
																																																htxt2 += ejo[j].name;
																																																htxt2 += "###host2###"
																																																harr2.push(htxt2);
																																																htxt2 = "";
																																															}else
																																															{
																																																htxt2 += ejo[j].name;
																																																htxt2 += "###host1###"
																																																harr2.push(htxt2);
																																																htxt2 = "";
																																															}
																																														}
																																														obj.hostarray = harr2.toString();

																																														
																																														var zz = obj.profileprotectlist;
																																														var str2 = [];
																																														var init2 = "";
																																														if(zz !== null)
																																														{
																																															for(var i = 0; i < zz.length; i++)
																																															{
																																																if(zz[i] === '#')
																																																{
																																																	str2.push(parseInt(init2));
																																																	init2 = "";
																																																	continue;
																																																}else
																																																{
																																																	init2 = init2 + zz[i];
																																																	continue;
																																																}
																																															}
																																														}
																																														
																																														
																																														if(str2.length > 0)
																																														{
																																															var use = ""
																																															for(var j = 0; j < str2.length; j++)
																																															{
																																																if(j == 0)
																																																	use = " WHERE id = " + str2[j]
																																																else
																																																	use += " OR id = " + str2[j]
																																															}
																																															var ttypes2 =
																																																	"SELECT name FROM transactiontype " + use + ";";
																																															pool.query(ttypes2, (err,  types2) => { 
																																																if (err) 
																																																{
																																																	obj.status = 200;
																																																	obj.message = "Success. Transaction Type Error";
																																																	obj.data = tconfig;
																																																	return res.header("Content-Type",'application/json').status(500).send(obj);
																																																}
																																																else
																																																{
																																																	if(types2.rows.length > 0)
																																																	{
																																																		var txnarr2 = [];
																																																		var txntxt2 = "";
																																																		
																																																		for(var i = 0; i < types2.rows.length; i++)
																																																		{
																																																			txntxt2 += "name - " + types2.rows[i].name;
																																																			txntxt2 += "###"
																																																			txnarr2.push(txntxt2);
																																																			txntxt2 = "";
																																																		}
																																																		obj.protectlist = txnarr2.toString();

																																																		
																																																		const h2 =
																																																			"SELECT * FROM host WHERE id = $1";
																																																		pool.query(h2, [obj.profilehost2id], (err,  hostid2) => { 
																																																			if (err) 
																																																			{
																																																				obj.status = 200;
																																																				obj.message = "Tid has Profile issues. Contact Admin";
																																																				obj.errordata = null;
																																																				res.header("Content-Type",'application/json').status(500).send(obj);
																																																			}
																																																			else
																																																			{
																																																				if(hostid2.rows.length < 1)
																																																				{
																																																					obj.status = 200;
																																																					obj.message = "iap Tid has Callhome issues. Contact Admin";
																																																					obj.errordata = null;
																																																					return res.header("Content-Type",'application/json').status(500).send(obj);
																																																				}else
																																																				{
																																																					obj.hostid2name = hostid2.rows[0].name;
																																																					obj.host2ip = hostid2.rows[0].ip;
																																																					obj.host2port = hostid2.rows[0].port;
																																																					obj.host2ssl = hostid2.rows[0].ssl;
																																																					obj.host2friendlyname = hostid2.rows[0].friendlyname;
																																																					obj.host2mestype = hostid2.rows[0].mestype;
																																																					
																																																					const sk2 =
																																																						"SELECT * FROM keys WHERE id = $1";
																																																					pool.query(sk2, [obj.profilefswitchkeyid], (err,  swk2) => { 
																																																						if (err) 
																																																						{
																																																							obj.status = 200;
																																																							obj.message = "Tid has Profile issues. Contact Admin";
																																																							obj.errordata = null;
																																																							res.header("Content-Type",'application/json').status(500).send(obj);
																																																						}
																																																						else
																																																						{
																																																							if(swk2.rows.length < 1)
																																																							{
																																																								obj.status = 200;
																																																								obj.message = "1am Tid has Callhome issues. Contact Admin";
																																																								obj.errordata = null;
																																																								return res.header("Content-Type",'application/json').status(500).send(obj);
																																																							}else
																																																							{
																																																								obj.swk2name = swk2.rows[0].name;
																																																								obj.swk2component1 = swk2.rows[0].component1;
																																																								obj.swk2component2 = swk2.rows[0].component2;
																																																								
																																																								if(obj.profilerlogoid !== "0")
																																																								{
																																																									const lg =
																																																										"SELECT * FROM logos WHERE id = $1";
																																																									pool.query(lg, [obj.profilerlogoid], (err,  logo) => { 
																																																										if (err) 
																																																										{
																																																											obj.status = 200;
																																																											obj.message = "Tid has Logo issues. Contact Admin";
																																																											obj.errordata = null;
																																																											res.header("Content-Type",'application/json').status(500).send(obj);
																																																										}
																																																										else
																																																										{
																																																											if(logo.rows.length < 1)
																																																											{
																																																												obj.status = 200;
																																																												obj.message = "1an Tid has Callhome issues. Contact Admin";
																																																												obj.errordata = null;
																																																												return res.header("Content-Type",'application/json').status(500).send(obj);
																																																											}else
																																																											{
																																																												obj.logorversion =  logo.rows[0].version;
																																																												obj.logorfilename =  logo.rows[0].filename;
																																																												obj.logordescription =  logo.rows[0].description;
																																																												obj.logorbankname =  logo.rows[0].bankname;
																																																												obj.logorbankcode =  logo.rows[0].bankcode;
																																																												obj.logordownload =  logo.rows[0].download;
																																																												obj.logorisreceipt =  logo.rows[0].isreceipt;
																																																												
																																																												
																																																												if(obj.profileblogoid !== "0")
																																																												{
																																																													const lg =
																																																														"SELECT * FROM logos WHERE id = $1";
																																																													pool.query(lg, [obj.profileblogoid], (err,  logo) => { 
																																																														if (err) 
																																																														{
																																																															obj.status = 200;
																																																															obj.message = "Tid has Logo issues. Contact Admin";
																																																															obj.errordata = null;
																																																															res.header("Content-Type",'application/json').status(500).send(obj);
																																																														}
																																																														else
																																																														{
																																																															if(logo.rows.length < 1)
																																																															{
																																																																obj.status = 200;
																																																																obj.message = "Tid has Callhome issues. Contact Admin";
																																																																obj.errordata = null;
																																																																return res.header("Content-Type",'application/json').status(500).send(obj);
																																																															}else
																																																															{
																																																																obj.logobversion =  logo.rows[0].version;
																																																																obj.logobfilename =  logo.rows[0].filename;
																																																																obj.logobdescription =  logo.rows[0].description;
																																																																obj.logobbankname =  logo.rows[0].bankname;
																																																																obj.logobbankcode =  logo.rows[0].bankcode;
																																																																obj.logobdownload =  logo.rows[0].download;
																																																																obj.logobisreceipt =  logo.rows[0].isreceipt;
																																																																
																																																																obj.status = 200;
																																																																obj.message = "Success";
																																																																return res.header("Content-Type",'application/json').status(200).send(obj);
																																																																
																																																															}
																																																														}
																																																													});
																																																												}else
																																																												{
																																																													obj.status = 200;
																																																													obj.message = "Success";
																																																													return res.header("Content-Type",'application/json').status(200).send(obj);
																																																												}
																																																											}
																																																										}
																																																									});
																																																								}else
																																																								{
																																																									obj.status = 200;
																																																									obj.message = "Success";
																																																									return res.header("Content-Type",'application/json').status(200).send(obj);
																																																								}
																																																								
																																																							}
																																																						}
																																																					});
																																																					
																																																				}
																																																			}
																																																		});


																																																	}
																																																}
																																															});
																																														}else
																																														{
																																															obj.status = 200;
																																															obj.message = "Tid has protectlist issues. Contact Admin";
																																															obj.errordata = tconfig;
																																															return res.header("Content-Type",'application/json').status(500).send(obj);
																																														}	
																																													}
																																												});	
																																											}
																																										}
																																									});
																																									
																																								}else
																																								{
																																									obj.status = 200;
																																									obj.message = "Tid has transaction issues. Contact Admin";
																																									obj.errordata = tconfig;
																																									return res.header("Content-Type",'application/json').status(500).send(obj);
																																								}
																																								
																																							}
																																						}
																																					});
																																					
																																				}
																																			}
																																		});
																																	}
																																}
																															});
																														}
																													}
																												});	
																											}
																										}
																									});
																								}
																							}
																						});
																					}
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
							}
						});
                    }
                }
            }
		});
    }catch(e)
    {
        logger.error("Profile Download from: " + req.clientIp + ". Error Occurred ");
        res.header("Content-Type",'application/json').status(500).send({});
    }
});

router.get("/mpos", function(req, res)
{
    try
    {
		var brand = req.headers.brand;
		var model = req.headers.model;
		var serial = req.headers.serial;
		var appversion = req.headers.appversion;

		logger.info("BRAND: " + brand);
		logger.info("MODEL: " + model);
		logger.info("SERIAL: " + serial);
		logger.info("SERIAL LENGTH: " + serial.length);
		logger.info("APPVERSION: " + appversion);

        var obj = new Object();
	    obj.timestamp = getDateTimeSpec();
        logger.info("Profile Download Request From: Ip: " + req.clientIp);
		const termConfig = "SELECT * FROM stock where serialnumber = $1";
		pool.query(termConfig, [serial], (err,  ddd) => {    
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
				if(ddd.rows.length == 0)
                {
                    obj.status = 200;
                    obj.message = "Serial Number not recognized.";
                    obj.errordata = null;
                    res.header("Content-Type",'application/json').status(500).send(obj);
                }else
                {
					var tid = ddd.rows[0].terminalid;
					const query5 =
                            "UPDATE terminalconfiguration SET terminalmanufacturer = $1, terminalmodel = $2, serialnumber = $3," + 
                            "initapplicationversion = $4 WHERE tid = $5";
                    pool.query(query5, [brand, model, serial, appversion, tid], (err,  r) => 
                    {    
                        if (err) 
                        {
                            obj.status = 200;
                            obj.message = "Tid has issues. Contact Admin";
                            obj.errordata = null;
                            res.header("Content-Type",'application/json').status(500).send(obj);
                        }
                        else
                        {
							var qry3 =
							"UPDATE stock SET terminalid = $1, appversion = $2" + 
							" WHERE serialnumber = $3";
							pool.query(qry3, [tid, appversion, serial], (err, check) => {
								if (err) 
								{
									logger.error("Channels Profile Put Session Database Issue " + req.clientIp);
									res.status(500).send({"status": 500, "message": "Try Later"});
								}else
								{
									const termConfig = "SELECT * FROM terminalconfiguration where tid = $1 AND ifavailable = $2";
        							pool.query(termConfig, [tid, "true"], (err,  config) => {    
										if(config.rows.length == 0)
										{
											obj.status = 200;
											obj.message = "Tid not profiled.";
											obj.errordata = null;
											res.header("Content-Type",'application/json').status(500).send(obj);
										}else
										{
											var tconfig = config.rows[0];
											obj.tid = config.rows[0].tid;
											obj.mid = config.rows[0].mid;
											//obj.serialnumber = config.rows[0].serialnumber;
											obj.timestamp = getDateTimeSpec();
											//obj.terminalmodel = config.rows[0].terminalmodel;
											//obj.initapplicationversion = config.rows[0].initapplicationversion;
											obj.merchantname = config.rows[0].merchantname;
											obj.merchantaddress = config.rows[0].merchantaddress;
											obj.adminpin = config.rows[0].adminpin;
											obj.merchantpin = config.rows[0].merchantpin;
											obj.changepin = config.rows[0].changepin;
											//obj.contactname = config.rows[0].contactname;
											//obj.contactphone = config.rows[0].contactphone;
											//obj.email = config.rows[0].email;
											obj.mcc = config.rows[0].mcc;
											//obj.datecreated = config.rows[0].datecreated;
											//obj.namecreated = config.rows[0].namecreated;
											//obj.datemodified = config.rows[0].datemodified;
											//obj.namemodified = config.rows[0].namemodified;
											//obj.lga = config.rows[0].lga;
											//obj.appname = config.rows[0].appname;
											//obj.country = config.rows[0].country;
											//obj.countrycode = config.rows[0].countrycode;
											//obj.maker = config.rows[0].maker;
											//obj.checker = config.rows[0].checker;
											//obj.profilename = config.rows[0].profilename;
											//obj.terminalmanufacturer = config.rows[0].terminalmanufacturer;
											obj.blocked = config.rows[0].blocked;
											obj.blockedpin = config.rows[0].blockedpin;
											obj.ownerusername = config.rows[0].ownerusername;
											obj.superagent = config.rows[0].superagent;
											obj.dialogheading = config.rows[0].dialogheading;
											//obj.simserial = config.rows[0].simserial;
											//obj.simnumber = config.rows[0].simnumber;
											//obj.simname = config.rows[0].simname;
											//obj.accountname = config.rows[0].accountname;
											//obj.accountcode = config.rows[0].accountcode;
											//obj.accountnumber = config.rows[0].accountnumber;
											//obj.accountbank = config.rows[0].accountbank;
											//obj.ifavailable = config.rows[0].ifavailable;
											//obj.profileid = config.rows[0].profileid;
											obj.ownerusername = config.rows[0].ownerusername;
											obj.stampduty = config.rows[0].stampduty;
											obj.msc = config.rows[0].msc;
											obj.switchfee = config.rows[0].switchfee;
											obj.tmsfeerule = config.rows[0].tmsfeerule;
											obj.superagentfeerule = config.rows[0].superagentfeerule;
											obj.ktransferrule = config.rows[0].tmstransferrule;
											obj.satfeerule = config.rows[0].superagenttransferrule;
											obj.tmo = config.rows[0].tmo;
											obj.sanef = config.rows[0].sanefnumber;
											obj.percentagerule = config.rows[0].percentagerule;
											obj.maxamount = config.rows[0].maxamount;
											
											const appl =
												`SELECT * FROM terminalapplications WHERE brand = $1 AND model = $2`;
											pool.query(appl, [brand, model], (err,  applic) => {    
												if (err) 
												{
													obj.status = 200;
													obj.message = "Tid has terminalapplication issues. Contact Admin";
													obj.data = tconfig;
													return res.header("Content-Type",'application/json').status(500).send(obj);
												}else
												{
													if(applic.rows.length < 1)
													{
														/*obj.appversion = null;
														obj.appbrand = null;
														obj.appdescription = null;
														obj.appmodel = null;
														obj.appfix = null;
														obj.appterminals = null;
														obj.appupdated = null;
														obj.appremarks = null;*/
													}
													else
													{
														var ap = applic.rows;
														for(var i = 0; i < ap.length; i++)
														{
															if (ap[i].terminals.indexOf("ALL " + brand + " TERMINALS") >= 0) 
															{
																obj.appversion = applic.rows[i].version;
																obj.appbrand = applic.rows[i].brand;
																obj.appdescription = applic.rows[i].description;
																obj.appmodel = applic.rows[i].model;
																obj.appfix = applic.rows[i].fix;
																obj.appterminals = applic.rows[i].terminals;
																obj.appupdated = applic.rows[i].updated;
																obj.appremarks = applic.rows[i].remarks;
																break;
															} else if(ap[i].terminals.indexOf(tid) >= 0) 
															{
																obj.appversion = applic.rows[i].version;
																obj.appbrand = applic.rows[i].brand;
																obj.appdescription = applic.rows[i].description;
																obj.appmodel = applic.rows[i].model;
																obj.appfix = applic.rows[i].fix;
																obj.appterminals = applic.rows[i].terminals;
																obj.appupdated = applic.rows[i].updated;
																obj.appremarks = applic.rows[i].remarks;
																break;
															}
														}
														if(appversion === obj.appversion)
														{
															/*obj.appversion = null;
															obj.appbrand = null;
															obj.appdescription = null;
															obj.appmodel = null;
															obj.appfix = null;
															obj.appterminals = null;
															obj.appupdated = null;
															obj.appremarks = null;*/
														}
													}

													const pro =
														"SELECT * FROM profile WHERE id = $1 AND ifavailable = $2";
													pool.query(pro, [config.rows[0].profileid, "true"], (err,  profile) => { 
														if (err) 
														{
															obj.status = 200;
															obj.message = "Tid has Profile issues. Contact Admin";
															obj.errordata = null;
															res.header("Content-Type",'application/json').status(500).send(obj);
														}
														else
														{
															if(profile.rows.length < 1)
															{
																obj.status = 200;
																obj.message = "Tid has Profile issues. Contact Admin";
																obj.errordata = null;
																return res.header("Content-Type",'application/json').status(500).send(obj);
															}
															//obj.profilename = profile.rows[0].name;
															//obj.profileremarks = profile.rows[0].remarks;
															//obj.profilecallhomeid = profile.rows[0].callhomeid;
															//obj.profilecommsid = profile.rows[0].commsid;
															//obj.profilereceiptid = profile.rows[0].receiptid;
															//obj.profilehostid = profile.rows[0].hostid;
															//obj.profileswitchkeyid = profile.rows[0].switchkeyid;
															//obj.profilecurrencyid = profile.rows[0].currencyid;
															//obj.profilebankid = profile.rows[0].bankid;
															//obj.profiletransactiontypesarray = profile.rows[0].transactiontypesarray;
															//obj.profilecardschemekeytypes = profile.rows[0].cardschemekeytypes;
															obj.profilevas = profile.rows[0].vas;
															obj.profileprotectlist = profile.rows[0].protectlist;
															//obj.profileotherimportant = profile.rows[0].otherimportant;
															//obj.profilehost2id = profile.rows[0].host2id;
															//obj.profilefswitchkeyid = profile.rows[0].fswitchkeyid;
															//obj.profilerlogoid = profile.rows[0].rlogoid;
															//obj.profileblogoid = profile.rows[0].blogoid;
															//obj.profilehostarray = profile.rows[0].hostarray;
															//obj.profiletmspay = profile.rows[0].tmspay;
															
															const ce =
																"SELECT * FROM callhome WHERE id = $1";
															pool.query(ce, [profile.rows[0].callhomeid], (err,  ch) => { 
																if (err) 
																{
																	obj.status = 200;
																	obj.message = "Tid has Profile issues. Contact Admin 1x";
																	obj.errordata = err;
																	res.header("Content-Type",'application/json').status(500).send(obj);
																}
																else
																{
																	if(ch.rows.length < 1)
																	{
																		obj.status = 200;
																		obj.message = "2x. Tid has Callhome issues. Contact Admin";
																		obj.errordata = err;
																		return res.header("Content-Type",'application/json').status(500).send(obj);
																	}else
																	{
																		//obj.chname = ch.rows[0].name;
																		obj.chinterval = ch.rows[0].interval;
																		obj.chip = ch.rows[0].ip;
																		obj.chport = ch.rows[0].port;
																		//obj.chremotedownloadtime = ch.rows[0].remotedownloadtime;
																		//obj.chcounts = ch.rows[0].count;
																		
																		const cc =
																			"SELECT * FROM comms WHERE id = $1";
																		pool.query(cc, [profile.rows[0].commsid], (err,  com) => { 
																			if (err) 
																			{
																				obj.status = 200;
																				obj.message = "Tid has Profile issues. Contact Admin";
																				obj.errordata = null;
																				return res.header("Content-Type",'application/json').status(500).send(obj);
																			}
																			else
																			{
																				if(com.rows.length < 1)
																				{
																					obj.status = 200;
																					obj.message = "3x Tid has Callhome issues. Contact Admin";
																					obj.errordata = null;
																					return res.header("Content-Type",'application/json').status(500).send(obj);
																				}else
																				{
																					//obj.comname = com.rows[0].name;
																					obj.comusername = com.rows[0].username;
																					//obj.comgateway = com.rows[0].gateway;
																					//obj.comip = com.rows[0].ip;
																					//obj.comport = com.rows[0].port;
																					obj.comapn = com.rows[0].apn;
																					obj.compassword = com.rows[0].password;
																					//obj.comremarks = com.rows[0].remarks;
																					//obj.comcommstype = com.rows[0].commstype;
																					//obj.comipmode = com.rows[0].ipmode;
																					
																					const rp =
																						"SELECT * FROM receipt WHERE id = $1";
																					pool.query(rp, [profile.rows[0].receiptid], (err,  rpt) => { 
																						if (err) 
																						{
																							obj.status = 200;
																							obj.message = "Tid has Profile issues. Contact Admin";
																							obj.errordata = null;
																							res.header("Content-Type",'application/json').status(500).send(obj);
																						}
																						else
																						{
																							if(rpt.rows.length < 1)
																							{
																								obj.status = 200;
																								obj.message = "4x Tid has Callhome issues. Contact Admin";
																								obj.errordata = null;
																								return res.header("Content-Type",'application/json').status(500).send(obj);
																							}else
																							{
																								/*
																								obj.rptname = rpt.rows[0].name;
																								obj.rptfootertext = rpt.rows[0].footertext;
																								obj.rptcustomercopylabel = rpt.rows[0].customercopylabel;
																								obj.rptmerchantcopylabel = rpt.rows[0].merchantcopylabel;
																								obj.rptfootnotelabel = rpt.rows[0].footnotelabel;
																								obj.rptnormalfontsize = rpt.rows[0].normalfontsize;
																								obj.rptheaderfontsize = rpt.rows[0].headerfontsize;
																								obj.rptamountfontsize = rpt.rows[0].amountfontsize;
																								obj.rptprintmerchantcopynumber = rpt.rows[0].printmerchantcopynumber;
																								obj.rptprintclientcopynumber = rpt.rows[0].printclientcopynumber;
																								obj.rptshowlogo = rpt.rows[0].showlogo;
																								obj.rptshowbarcode = rpt.rows[0].showbarcode;
																								obj.rptsaveforreceipt = rpt.rows[0].saveforreceipt;
																								*/
																								const hi =
																									"SELECT * FROM host WHERE id = $1";
																								pool.query(hi, [profile.rows[0].hostid], (err,  hostid) => { 
																									if (err) 
																									{
																										obj.status = 200;
																										obj.message = "Tid has Profile issues. Contact Admin";
																										obj.errordata = null;
																										res.header("Content-Type",'application/json').status(500).send(obj);
																									}
																									else
																									{
																										if(hostid.rows.length < 1)
																										{
																											obj.status = 200;
																											obj.message = "5x Tid has Callhome issues. Contact Admin";
																											obj.errordata = null;
																											return res.header("Content-Type",'application/json').status(500).send(obj);
																										}else
																										{
																											obj.hostidname = hostid.rows[0].name;
																											obj.hostip = hostid.rows[0].ip;
																											obj.hostport = hostid.rows[0].port;
																											obj.hostssl = hostid.rows[0].ssl;
																											obj.hostfriendlyname = hostid.rows[0].friendlyname;
																											//obj.hostmestype = hostid.rows[0].mestype;

																											
																											const sk =
																												"SELECT * FROM keys WHERE id = $1";
																											pool.query(sk, [profile.rows[0].fswitchkeyid], (err,  swk) => { 
																												if (err) 
																												{
																													obj.status = 200;
																													obj.message = "Tid has Profile issues. Contact Admin";
																													obj.errordata = null;
																													res.header("Content-Type",'application/json').status(500).send(obj);
																												}
																												else
																												{
																													if(swk.rows.length < 1)
																													{
																														obj.status = 200;
																														obj.message = "6x Tid has Callhome issues. Contact Admin";
																														obj.errordata = null;
																														return res.header("Content-Type",'application/json').status(500).send(obj);
																													}else
																													{
																														//obj.swkname = swk.rows[0].name;
																														obj.swkcomponent1 = swk.rows[0].component1;
																														//obj.swkcomponent2 = swk.rows[0].component2;
																														
																														const cu =
																															"SELECT * FROM currency WHERE id = $1";
																														pool.query(cu, [profile.rows[0].currencyid], (err,  cur) => { 
																															if (err) 
																															{
																																obj.status = 200;
																																obj.message = "Tid has Profile issues. Contact Admin";
																																obj.errordata = null;
																																res.header("Content-Type",'application/json').status(500).send(obj);
																															}
																															else
																															{
																																if(cur.rows.length < 1)
																																{
																																	obj.status = 200;
																																	obj.message = "7x Tid has Callhome issues. Contact Admin";
																																	obj.errordata = null;
																																	return res.header("Content-Type",'application/json').status(500).send(obj);
																																}else
																																{
																																	//obj.curname =  cur.rows[0].name;
																																	obj.curabbreviation =  cur.rows[0].abbreviation;
																																	obj.curcode =  cur.rows[0].code;
																																	//obj.curminorunit =  cur.rows[0].minorunit;
																																	//obj.curremarks =  cur.rows[0].remarks;
																																	
																																	const bn =
																																		"SELECT * FROM banks WHERE id = $1";
																																	pool.query(bn, [profile.rows[0].bankid], (err,  bnk) => { 
																																		if (err) 
																																		{
																																			obj.status = 200;
																																			obj.message = "Tid has Profile issues. Contact Admin";
																																			obj.errordata = null;
																																			return res.header("Content-Type",'application/json').status(500).send(obj);
																																		}
																																		else
																																		{
																																			if(bnk.rows.length < 1)
																																			{
																																				obj.status = 200;
																																				obj.message = "8x Tid has Callhome issues. Contact Admin";
																																				obj.errordata = null;
																																				return res.header("Content-Type",'application/json').status(500).send(obj);
																																			}else
																																			{
																																				/*obj.bnkname =  bnk.rows[0].name;
																																				obj.bnkcode =  bnk.rows[0].code;
																																				obj.bnkremarks =  bnk.rows[0].remarks;*/
																																				
																																				//var tt = obj.profiletransactiontypesarray;
																																				var tt = profile.rows[0].transactiontypesarray;
																																				var str = [];
																																				var init = "";
																																				for(var i = 0; i < tt.length; i++)
																																				{
																																					if(tt[i] === '#')
																																					{
																																						str.push(parseInt(init));
																																						init = "";
																																						continue;
																																					}else
																																					{
																																						init = init + tt[i];
																																						continue;
																																					}
																																				}
																																				
																																				if(str.length > 0)
																																				{
																																					var use = ""
																																					for(var j = 0; j < str.length; j++)
																																					{
																																						if(j == 0)
																																							use = " WHERE id = " + str[j]
																																						else
																																							use += " OR id = " + str[j]
																																					}
																																					var ttypes =
																																					"SELECT * FROM transactiontype " + use + " ORDER BY position ASC;";
																																					pool.query(ttypes, (err,  types) => {    
																																						if (err) 
																																						{
																																							obj.status = 200;
																																							obj.message = "Tid has transaction issues. Contact Admin";
																																							obj.errordata = tconfig;
																																							return res.header("Content-Type",'application/json').status(500).send(obj);
																																						}else
																																						{
																																							if(types.rows.length < 1)
																																							{
																																								obj.status = 200;
																																								obj.message = "Success. No Transaction Type";
																																								obj.data = tconfig;
																																								return res.header("Content-Type",'application/json').status(500).send(obj);
																																							}
																																							else
																																							{
																																								var txnarr = [];
																																								var txntxt = "";
																																								
																																								for(var i = 0; i < types.rows.length; i++)
																																								{
																																									txntxt += "name - " + types.rows[i].name;
																																									txntxt += "###common - " + types.rows[i].commonname;
																																									/*txntxt += "###transtype - " + types.rows[i].transtype;
																																									txntxt += "###uses - " + types.rows[i].uses
																																									txntxt += "###position - " + types.rows[i].position
																																									txntxt += "###discountpercent - " + types.rows[i].discountpercent
																																									txntxt += "###discount - " + types.rows[i].discount
																																									txntxt += "###commissionpercent - " + types.rows[i].commissionpercent
																																									txntxt += "###commission - " + types.rows[i].commission
																																									txntxt += "###baseamtpercentage - " + types.rows[i].baseamtpercentage
																																									txntxt += "###baseamtfixed - " + types.rows[i].baseamtfixed
																																									txntxt += "###remarks - " + types.rows[i].remarks*/
																																									txnarr.push(txntxt);
																																									txntxt = "";
																																								}
																																								
																																								obj.transactions = txnarr.toString();
																																								
																																								var ha = obj.profilehostarray;
																																								var arry3 = [];
																																								var arry4 = [];
																																								var ar3 = "";
																																								var ar4 = "";
																																								var loop = 0;
																																								if(ha)
																																								{
																																									for(var j = 0; j < ha.length; j++)
																																									{
																																										if(ha.charAt(j) === '#')
																																										{
																																											loop = 0;
																																											arry4.push(ar4);
																																											ar4 = "";
																																										}else if(ha.charAt(j) === ' ')
																																										{
																																											loop = 1;
																																											arry3.push(parseInt(ar3));
																																											ar3 = "";
																																											j += 2;
																																										}else
																																										{
																																											if(loop === 0)
																																											{
																																												ar3 += ha.charAt(j);
																																											}else
																																											{
																																												ar4 += ha.charAt(j);
																																											}
																																										}
																																									}
																																								}

																																								const tta =
																																									`SELECT name, position FROM transactiontype ORDER BY position ASC`;
																																								pool.query(tta, (err,  ttar) => {    
																																									if (err) 
																																									{
																																										console.log(err);
																																										obj.status = 200;
																																										obj.message = "Success. Transaction Host Error";
																																										obj.data = tconfig;
																																										return res.header("Content-Type",'application/json').status(500).send(obj);
																																									}
																																									else
																																									{
																																										var harr2 = [];
																																										var htxt2 = "";
																																										var ejo = ttar.rows;
																																										for(var j = 0; j < ejo.length; j++) 
																																										{
																																											var ch = ejo[j].id;
																																											var k = arry3.indexOf(ch);
																																											
																																											if(arry4[k] === 'h2')
																																											{
																																												htxt2 += ejo[j].name;
																																												htxt2 += "###host2###"
																																												harr2.push(htxt2);
																																												htxt2 = "";
																																											}else
																																											{
																																												htxt2 += ejo[j].name;
																																												htxt2 += "###host1###"
																																												harr2.push(htxt2);
																																												htxt2 = "";
																																											}
																																										}
																																										//obj.hostarray = harr2.toString();

																																										
																																										var zz = obj.profileprotectlist;
																																										var str2 = [];
																																										var init2 = "";
																																										if(zz !== null)
																																										{
																																											for(var i = 0; i < zz.length; i++)
																																											{
																																												if(zz[i] === '#')
																																												{
																																													str2.push(parseInt(init2));
																																													init2 = "";
																																													continue;
																																												}else
																																												{
																																													init2 = init2 + zz[i];
																																													continue;
																																												}
																																											}
																																										}
																																										
																																										
																																										if(str2.length > 0)
																																										{
																																											var use = ""
																																											for(var j = 0; j < str2.length; j++)
																																											{
																																												if(j == 0)
																																													use = " WHERE id = " + str2[j]
																																												else
																																													use += " OR id = " + str2[j]
																																											}
																																											var ttypes2 =
																																													"SELECT name FROM transactiontype " + use + ";";
																																											pool.query(ttypes2, (err,  types2) => { 
																																												if (err) 
																																												{
																																													obj.status = 200;
																																													obj.message = "Success. Transaction Type Error";
																																													obj.data = tconfig;
																																													return res.header("Content-Type",'application/json').status(500).send(obj);
																																												}
																																												else
																																												{
																																													if(types2.rows.length > 0)
																																													{
																																														var txnarr2 = [];
																																														var txntxt2 = "";
																																														
																																														for(var i = 0; i < types2.rows.length; i++)
																																														{
																																															txntxt2 += "name - " + types2.rows[i].name;
																																															txntxt2 += "###"
																																															txnarr2.push(txntxt2);
																																															txntxt2 = "";
																																														}
																																														obj.protectlist = txnarr2.toString();

																																														
																																														const h2 =
																																															"SELECT * FROM host WHERE id = $1";
																																														pool.query(h2, [profile.rows[0].host2id], (err,  hostid2) => { 
																																															if (err) 
																																															{
																																																obj.status = 200;
																																																obj.message = "Tid has Profile issues. Contact Admin";
																																																obj.errordata = null;
																																																res.header("Content-Type",'application/json').status(500).send(obj);
																																															}
																																															else
																																															{
																																																
																																																
																																																if(hostid2.rows.length < 1)
																																																{
																																																	obj.status = 200;
																																																	obj.message = "9x Tid has Callhome issues. Contact Admin";
																																																	obj.errordata = null;
																																																	return res.header("Content-Type",'application/json').status(500).send(obj);
																																																}else
																																																{
																																																	/*obj.hostid2name = hostid2.rows[0].name;
																																																	obj.host2ip = hostid2.rows[0].ip;
																																																	obj.host2port = hostid2.rows[0].port;
																																																	obj.host2ssl = hostid2.rows[0].ssl;
																																																	obj.host2friendlyname = hostid2.rows[0].friendlyname;
																																																	obj.host2mestype = hostid2.rows[0].mestype;*/
																																																	
																																																	const sk2 =
																																																		"SELECT * FROM keys WHERE id = $1";
																																																	pool.query(sk2, [profile.rows[0].switchkeyid], (err,  swk2) => { 
																																																		if (err) 
																																																		{
																																																			obj.status = 200;
																																																			obj.message = "Tid has Profile issues. Contact Admin";
																																																			obj.errordata = null;
																																																			res.header("Content-Type",'application/json').status(500).send(obj);
																																																		}
																																																		else
																																																		{
																																																			if(swk2.rows.length < 1)
																																																			{
																																																				obj.status = 200;
																																																				obj.message = "10x Tid has Callhome issues. Contact Admin";
																																																				obj.errordata = null;
																																																				return res.header("Content-Type",'application/json').status(500).send(obj);
																																																			}else
																																																			{
																																																				//obj.swk2name = swk2.rows[0].name;
																																																				//obj.swk2component1 = swk2.rows[0].component1;
																																																				//obj.swk2component2 = swk2.rows[0].component2;
																																																				
																																																				if(profile.rows[0].rlogoid !== "0")
																																																				{
																																																					const lg =
																																																						"SELECT * FROM logos WHERE id = $1";
																																																					pool.query(lg, [profile.rows[0].rlogoid], (err,  logo) => { 
																																																						if (err) 
																																																						{
																																																							obj.status = 200;
																																																							obj.message = "Tid has Logo issues. Contact Admin";
																																																							obj.errordata = null;
																																																							res.header("Content-Type",'application/json').status(500).send(obj);
																																																						}
																																																						else
																																																						{
																																																							if(logo.rows.length < 1)
																																																							{
																																																								obj.status = 200;
																																																								obj.message = "11x Tid has Callhome issues. Contact Admin";
																																																								obj.errordata = null;
																																																								return res.header("Content-Type",'application/json').status(500).send(obj);
																																																							}else
																																																							{
																																																								/*obj.logorversion =  logo.rows[0].version;
																																																								obj.logorfilename =  logo.rows[0].filename;
																																																								obj.logordescription =  logo.rows[0].description;
																																																								obj.logorbankname =  logo.rows[0].bankname;
																																																								obj.logorbankcode =  logo.rows[0].bankcode;
																																																								obj.logordownload =  logo.rows[0].download;
																																																								obj.logorisreceipt =  logo.rows[0].isreceipt;*/
																																																								
																																																								
																																																								if(profile.rows[0].blogoid !== "0")
																																																								{
																																																									const lg =
																																																										"SELECT * FROM logos WHERE id = $1";
																																																									pool.query(lg, [profile.rows[0].blogoid], (err,  logo) => { 
																																																										if (err) 
																																																										{
																																																											obj.status = 200;
																																																											obj.message = "Tid has Logo issues. Contact Admin";
																																																											obj.errordata = null;
																																																											res.header("Content-Type",'application/json').status(500).send(obj);
																																																										}
																																																										else
																																																										{
																																																											if(logo.rows.length < 1)
																																																											{
																																																												obj.status = 200;
																																																												obj.message = "12x Tid has Callhome issues. Contact Admin";
																																																												obj.errordata = null;
																																																												return res.header("Content-Type",'application/json').status(500).send(obj);
																																																											}else
																																																											{
																																																												/*obj.logobversion =  logo.rows[0].version;
																																																												obj.logobfilename =  logo.rows[0].filename;
																																																												obj.logobdescription =  logo.rows[0].description;
																																																												obj.logobbankname =  logo.rows[0].bankname;
																																																												obj.logobbankcode =  logo.rows[0].bankcode;
																																																												obj.logobdownload =  logo.rows[0].download;
																																																												obj.logobisreceipt =  logo.rows[0].isreceipt;*/
																																																												
																																																												//obj.status = 200;
																																																												//obj.message = "Success";
																																																												return res.header("Content-Type",'application/json').status(200).send(obj);
																																																												
																																																											}
																																																										}
																																																									});
																																																								}else
																																																								{
																																																									//obj.status = 200;
																																																									//obj.message = "Success";
																																																									return res.header("Content-Type",'application/json').status(200).send(obj);
																																																								}
																																																							}
																																																						}
																																																					});
																																																				}else
																																																				{
																																																					//obj.status = 200;
																																																					//obj.message = "Success";
																																																					return res.header("Content-Type",'application/json').status(200).send(obj);
																																																				}
																																																				
																																																			}
																																																		}
																																																	});
																																																	
																																																}
																																															}
																																														});


																																													}
																																												}
																																											});
																																										}else
																																										{
																																											obj.status = 200;
																																											obj.message = "Tid has protectlist issues. Contact Admin";
																																											obj.errordata = tconfig;
																																											return res.header("Content-Type",'application/json').status(500).send(obj);
																																										}	
																																									}
																																								});	
																																							}
																																						}
																																					});
																																					
																																				}else
																																				{
																																					obj.status = 200;
																																					obj.message = "Tid has transaction issues. Contact Admin";
																																					obj.errordata = tconfig;
																																					return res.header("Content-Type",'application/json').status(500).send(obj);
																																				}
																																				
																																			}
																																		}
																																	});
																																	
																																}
																															}
																														});
																													}
																												}
																											});
																										}
																									}
																								});	
																							}
																						}
																					});
																				}
																			}
																		});
																	}
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
            }
        });
    }catch(e)
    {
        logger.error("Profile Download from: " + req.clientIp + ". Error Occurred ");
        res.header("Content-Type",'application/json').status(500).send({});
    }
});

module.exports.router = router;