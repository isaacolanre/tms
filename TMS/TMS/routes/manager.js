var router = express.Router();

//Login Routes
router.use('/login/', require("./usermanager/login.js").router);
//Dashboard Route
router.use('/dashboard/', require("./dashboard/dashboard.js").router);
//Transaction Route
router.use('/transaction/', require("./transaction/transaction.js").router);
//Ejournal Route
router.use('/ejournal/', require("./transaction/ejournal.js").router);
//State Route
router.use('/state/', require("./state/state.js").router);
//Signup Route
router.use('/signup/', require("./signup/signup.js").router);
//Profile Route

//Wallet Route
router.use('/wallet/', require("./wallet/wallet.js").router);
//Terminal Setup

//Terminal Purchase
router.use('/purchase/', require("./purchase/purchase.js").router);



//Terminal Prices
router.use('/prices/', require("./prices/prices.js").router);



//Staff Mapping
router.use('/staffmapping/', require("./staffmapping/staffmapping.js").router);


//Messages Mapping
router.use('/messages/', require("./messages/messages.js").router);





//Settings
//Callhome, receipt, 
//host, communication
router.use("/settings/", require("./settings/settings.js").router);

//Inactive Route
router.use('/inactive/', require("./inactive/inactive.js").router);
//Ongoing Route
router.use('/ongoing/', require("./ongoing/ongoing.js").router);
//Instant Value Route
router.use('/instantvalue/', require("./settlement/instantvalue.js").router);
//Instant Value Settled
router.use('/settledinstant/', require("./settlement/instantvaluesettlement.js").router);
//Agency Instant
router.use('/agencyinstant/', require("./settlement/agencyinstant.js").router);
//Agency Settled
router.use('/settledagency/', require("./settlement/settledagency.js").router);
//Query
router.use('/query/', require("./externalapi/tms.js").router);

//App Download
router.use('/appdownload/', require("./externalapi/appdownload.js").router);
//Bills Download
router.use('/billing/', require("./externalapi/billsmenu.js").router);
//Callhome
router.use('/callhome/', require("./externalapi/broadcast.js").router);
//Ussd
router.use('/ussd/', require("./externalapi/ussd.js").router);
//Superagent
router.use('/reports/', require("./etranzact/reports.js").router);
//Processor
router.use('/processor/', require("./etranzact/funds.js").router);
//Bills
router.use('/paybills/', require("./etranzact/paybills.js").router);
//BODC
router.use('/bodc/', require("./etranzact/bodc.js").router);
//Intellifin
router.use('/intellifin/', require("./intellifin/intellifin.js").router);
//Keys Download
router.use('/keys/', require("./externalapi/keysdownload.js").router);
//Logo Download
router.use('/logodownload/', require("./externalapi/logodownload.js").router);
//Profile Download
router.use('/profile/', require("./externalapi/profiledownload.js").router);


//Pending
router.use("/pending/", require("./pending/pendings.js").router);
//Terminals
router.use("/terminals/", require("./terminal/terminal.js").router);
//Profile
router.use("/profile/", require("./profile/profiles.js").router);
//Transaction Types
router.use("/transactiontypes/", require("./transactiontypes/transactiontypes.js").router);
//Stock
router.use("/stock/", require("./stock/stock.js").router);
//Logo
router.use("/logo/", require("./logo/logos.js").router);
//Currency
router.use("/currency/", require("./currency/currency.js").router);
//Banks
router.use("/banks/", require("./banks/banks.js").router);
//Credits
router.use("/credits/", require("./credits/credits.js").router);
//Transaction Broadcast
router.use("/broadcast/", require("./broadcast/broadcasts.js").router);
//Card Keys
router.use("/cardkeys/", require("./cardkeys/cardkeys.js").router);
//Host Keys
router.use("/hostkeys/", require("./hostkeys/hostkeys.js").router);
//Remote update
router.use("/upgrade/", require("./upgrade/upgrades.js").router);
//User Signup
router.use("/usersignup/", require("./usermanager/usersignup.js").router);
//All Users
router.use('/tmsusers/', require("./usermanager/allusers.js").router);
//All Admins
router.use('/tmsadmins/', require("./usermanager/alladmins.js").router);
//All Others
router.use('/tmsothers/', require("./usermanager/allothers.js").router);
//Blocked Users
router.use('/tmsblocked/', require("./usermanager/blocked.js").router);
//Change password
router.use('/usermodify/', require("./usermanager/modify.js").router);

//Settlement Engine for VTU and BILLS PAYMENT
router.use('/vtusettlement/', require("./settlement/vtu.js").router);
router.use('/agencysettlement/', require("./settlement/agency.js").router);
router.use('/failedtxns/', require("./settlement/failed.js").router);

//tms Retail
router.use('/retail/', require("./retail/retail.js").router);
//Get Active Banks
router.use('/getbanks/', require("./etranzact/banks.js").router);

router.all("*", function(req, res)
{
    logger.info("In Manager No route: " + req.url);
    console.log(req.method);
    logger.info("Wrong URL. Redirecting to home. From: " + req.clientIp + ". Time: " + new Date().toLocaleString());
    res.redirect("/");
});

module.exports = router;