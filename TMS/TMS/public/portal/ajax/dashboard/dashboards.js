var role;
var username;
var tids;
var transactions;
var states;
var complaints;//Update when web is ready
var vtmo;

getDateTimeSpec = function()
    {
        var str = "";
        var currentTime = new Date();
        var year = currentTime.getFullYear();
        var mnt = currentTime.getMonth() + 1;
        var day = currentTime.getDate();
        var hours = currentTime.getHours();
        var minutes = currentTime.getMinutes();
        var seconds = currentTime.getSeconds();
        if(mnt < 10)
        {
            mnt = "0" + mnt;
        }
        if(day < 10)
        {
            day = "0" + day
        }
        if (hours < 10) {
            hours = "0" + hours;
        }
        if (minutes < 10) {
            minutes = "0" + minutes;
        }
        if (seconds < 10) {
            seconds = "0" + seconds;
        }
        str += year + "-" + mnt + "-" + day + " " + hours + ":" + minutes + ":" + seconds;
        return str;
    }

function getMonth(month)
{
    var loop = 0;
    var mnt = "";
    for(var i = 0; i < month.length; i++)
    {
        if(loop === 0)
        {
            if(month.charAt(i) === '-')
            {
                loop++;
                continue;   
            }
        }else
        {
            if(month.charAt(i) === '-')
                break;
            else
                mnt += month.charAt(i);
        }
    }
    if(mnt === "01" || mnt === "1")
        return "Jan";
    if(mnt === "02" || mnt === "2")
        return "Feb";
    if(mnt === "03" || mnt === "3")
        return "March";
    if(mnt === "04" || mnt === "4")
        return "April";
    if(mnt === "05" || mnt === "5")
        return "May";
    if(mnt === "06" || mnt === "6")
        return "June";
    if(mnt === "07" || mnt === "7")
        return "July";
    if(mnt === "08" || mnt === "8")
        return "Aug";
    if(mnt === "09" || mnt === "9")
        return "Sep";
    if(mnt === "10" || mnt === "10")
        return "Oct";
    if(mnt === "11" || mnt === "11")
        return "Nov";
    if(mnt === "12" || mnt === "12")
        return "Dec";
    
}

function setResponseCode(code)
{
	if(code == null)
	return "No Response";
	if(code == "00")
    {
        return "Approved..";
    }else if(code == "01")
    {
        return "Refer to card issuer, special condition";
    }else if(code == "02")
    {
        return "Refer to card issuer";
    }else if(code == "03")
    {
        return "Invalid merchant";
    }else if(code == "04")
    {
        return "Pick-up card";
    }else if(code == "05")
    {
        return "Do not honor";
    }else if(code == "06")
    {
        return "Error";
    }else if(code == "07")
    {
        return "Pick-up card, special condition";
    }else if(code == "08")
    {
        return "Honor with identification";
    }else if(code == "09")
    {
        return "Request in progress";
    }else if(code == "10")
    {
        return "Approved, partial";
    }else if(code == "11")
    {
        return "Approved, VIP";
    }else if(code == "12")
    {
        return "Invalid transaction";
    }else if(code == "13")
    {
        return "Invalid amount";
    }else if(code == "14")
    {
        return "Invalid card number";
    }else if(code == "15")
    {
        return "No such issuer";
    }else if(code == "16")
    {
        return "Approved, update track 3";
    }else if(code == "17")
    {
        return "Customer cancellation";
    }else if(code == "18")
    {
        return "Customer dispute";
    }else if(code == "19")
    {
        return "Re-enter transaction";
    }else if(code == "20")
    {
        return "Invalid response";
    }else if(code == "21")
    {
        return "No action taken";
    }else if(code == "22")
    {
        return "Suspected malfunction";
    }else if(code == "23")
    {
        return "Unacceptable transaction fee";
    }else if(code == "24")
    {
        return "File update not supported";
    }else if(code == "25")
    {
        return "Unable to locate record";
    }else if(code == "26")
    {
        return "Duplicate record";
    }else if(code == "27")
    {
        return "File update field edit error";
    }else if(code == "28")
    {
        return "File update file locked";
    }else if(code == "29")
    {
        return "File update failed";
    }else if(code == "30")
    {
        return "Format error";
    }else if(code == "31")
    {
        return "Bank not supported";
    }else if(code == "32")
    {
        return "Completed partially";
    }else if(code == "33")
    {
        return "Expired card, pick-up";
    }else if(code == "34")
    {
        return "Suspected fraud, pick-up";
    }else if(code == "35")
    {
        return "Contact acquirer, pick-up";
    }else if(code == "36")
    {
        return "Restricted card, pick-up";
    }else if(code == "37")
    {
        return "Call acquirer security, pick-up";
    }else if(code == "38")
    {
        return "PIN tries exceeded, pick-up";
    }else if(code == "39")
    {
        return "No credit account";
    }else if(code == "40")
    {
        return "Function not supported";
    }else if(code == "41")
    {
        return "Lost card, pick-up";
    }else if(code == "42")
    {
        return "No universal account";
    }else if(code == "43")
    {
        return "Stolen card, pick-up";
    }else if(code == "44")
    {
        return "No investment account";
    }else if(code == "45")
    {
        return "Account closed";
    }else if(code == "46")
    {
        return "Identification required";
    }else if(code == "47")
    {
        return "Identification cross-check required";
    }else if(code == "48")
    {
        return "Error";
    }else if(code == "49")
    {
        return "Error";
    }else if(code == "50")
    {
        return "Error";
    }else if(code == "51")
    {
        return "Insufficient funds";
    }else if(code == "52")
    {
        return "No check account";
    }else if(code == "53")
    {
        return "No savings account";
    }else if(code == "54")
    {
        return "Expired card";
    }else if(code == "55")
    {
        return "Incorrect PIN";
    }else if(code == "56")
    {
        return "No card record";
    }else if(code == "57")
    {
        return "Transaction not permitted to cardholder";
    }else if(code == "58")
    {
        return "Transaction not permitted on terminal";
    }else if(code == "59")
    {
        return "Suspected fraud";
    }else if(code == "60")
    {
        return "Contact acquirer";
    }else if(code == "61")
    {
        return "Exceeds withdrawal limit";
    }else if(code == "62")
    {
        return "Restricted card";
    }else if(code == "63")
    {
        return "Security violation";
    }else if(code == "64")
    {
        return "Original amount incorrect";
    }else if(code == "65")
    {
        return "Exceeds withdrawal frequency";
    }else if(code == "66")
    {
        return "Call acquirer security";
    }else if(code == "67")
    {
        return "Hard capture";
    }else if(code == "68")
    {
        return "Response received too late";
    }else if(code == "69")
    {
        return "Advice received too late";
    }else if(code == "70")
    {
        return "Error";
    }else if(code == "71")
    {
        return "Error";
    }else if(code == "72")
    {
        return "Error";
    }else if(code == "73")
    {
        return "Error";
    }else if(code == "74")
    {
        return "Error";
    }else if(code == "75")
    {
        return "PIN tries exceeded";
    }else if(code == "76")
    {
        return "Error";
    }else if(code == "77")
    {
        return "Intervene, bank approval required";
    }else if(code == "78")
    {
        return "Intervene, bank approval required for partial amount";
    }else if(code == "79")
    {
        return "Error";
    }else if(code == "80")
    {
        return "Error";
    }else if(code == "81")
    {
        return "Error";
    }else if(code == "82")
    {
        return "Error";
    }else if(code == "83")
    {
        return "Error";
    }else if(code == "84")
    {
        return "Error";
    }else if(code == "85")
    {
        return "Error";
    }
    
    else if(code == "86")
    {
        return "Could Not Connect";
    }else if(code == "87")
    {
        return "Could Not Connect";
    }else if(code == "88")
    {
        return "No Response From Nibss";
    }else if(code == "89")
    {
        return "No Response From Nibss";
    }
    
    else if(code == "90")
    {
        return "Cut-off in progress";
    }else if(code == "91")
    {
        return "Issuer or switch inoperative";
    }else if(code == "92")
    {
        return "Routing error";
    }else if(code == "93")
    {
        return "Violation of law";
    }else if(code == "94")
    {
        return "Duplicate transaction";
    }else if(code == "95")
    {
        return "Reconcile error";
    }else if(code == "96")
    {
        return "System malfunction";
    }else if(code == "97")
    {
        return "Reserved for future Postilion use";
    }else if(code == "98")
    {
        return "Exceeds cash limit";
    }else if(code == "99")
    {
        return "Error";
    }else
    {
        return "Response Unknown";
    }
}

function getAllStates()
{
    $.ajax({
		url: "/tms/state/getAllToday",
		async: true,
		dataType: 'json',
		success: function (data) {
            if(data === null)
            {
                console.log("Nothing came back... Keep it null");
                return;
            }
            states = data;
            $("#aucdiv").empty();
            var i = states.length - 1;
            var c = 0;
            for(; i > -1; i--, c++) {
                if(role !== "user")
                {
                    var j = 0;
                    var m = tids.length - 1;
                    for(; m > -1; m--) {
                        if(tids[m].tid === states[i].terminal_id)
                        {
                            j = 1;
                            break;
                        }
                    }
                    if(j == 0)
                    {
                        continue;
                    }
                }
                
                //var time = states[i].current_date_uzoezi.slice(0, 10);
                //var dat = parseInt(time.slice(8, 10)) + 1;

                var time = getDateTimeSpec().slice(0, 10);
                var dat = parseInt(time.slice(8, 10));

                var text = "<article class=\"media event\"><a class=\"pull-left date\"><p class=\"month\">" + getMonth(time) + "</p>" + 
                    "<p class=\"day\">" + dat + "</p></a><div class=\"media-body\"><a class=\"title\" href=\"#\">" + states[i].terminal_id + "</a>" +
                    "<p>" + states[i].printer_state + "</p></div></article>";
                $("#aucdiv").append(text);
                if(c >= 10)
                    break;
            }
		},
		error : function(xhr,errmsg,err) {
			
        }
	});
}

function parseTxnResponse()
{
    if(tids === null)
    {
        console.log("Tids not yet fetched");
    }else if(transactions === null)
    {
        console.log("Nothing came back... Keep it null");
    }else
    {
        var i = transactions.length - 1;
        var c = 0;
        var tt = 0;
        var ta = 0;
        var td = 0;

        var tmo = 0.00;
        var ptsp = 0.00;
        var iswcharge = 0.00;
        var iswdue = 0.00;
        var nibssmsc = 0.00;
        var nibssdue = 0.00;
        var tms = 0;
        var volume = 0.00;

        $("#apprtxndiv").empty();//Approved
        $("#declreason").empty();//Declined
        $("#rectrndiv").empty();//All txn
        for(; i > -1; i--, c++) {
            if(role !== "user")
            {
                var j = 0;
                var m = tids.length - 1;
                for(; m > -1; m--) {
                    if(tids[m].tid === transactions[i].terminal_id)
                    {
                        j = 1;
                        break;
                    }
                }
                if(j == 0)
                {
                    continue;
                }
            }else
            {
                var j = 0;
                var m = tids.length - 1;
                for(; m > -1; m--) {
                    if(tids[m].tid === transactions[i].terminal_id)
                    {
                        j = 1;
                        break;
                    }
                }
                if(j == 0)
                {
                    continue;
                }
            }
            
            if(transactions[i].paymentmode !== "CASH" && transactions[i].paymentmode !== "USSD" 
                && role === "user" && transactions[i].response_code === "00")
            {
                if(transactions[i].tap === "saturn.interswitchng.com443" || transactions[i].tap === "https://kimono.interswitchng.com")
                {
                    //Interswitch
                    iswdue = parseFloat(iswdue) + parseFloat(transactions[i].amount);
                    iswcharge = parseFloat(iswcharge) + parseFloat("15.00");
                    lvv = parseFloat(iswdue).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
                    $("#iswdue").text(lvv);
                    lvv = parseFloat(iswcharge).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
                    $("#iswcharge").text(lvv);
                    volume = parseFloat(volume) + parseFloat(transactions[i].amount);
                    famt = parseFloat(volume).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
                    $("#totalvolume").text(famt);
                }else
                {
                    //Nibbss
                    var amt = transactions[i].amount;
                    var t = parseFloat(amt);
                    var msc = ((0.5/100) * t).toFixed(2);
                    if(msc > 1000)
                        msc = 1000;
                    
                    nibssmsc = parseFloat(nibssmsc) + parseFloat(msc);
                    nibssdue = parseFloat(nibssdue) + parseFloat(transactions[i].amount);
                    lvv = parseFloat(nibssmsc).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
                    $("#nibssmsc").text(lvv);
                    lvv = parseFloat(nibssdue).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
                    $("#nibssdue").text(lvv);

                    var pts = (0.25 * msc).toFixed(2);
                    var tm = (0.25 * msc).toFixed(2);
                    var kar = (0.85 * pts).toFixed(2);

                    tmo = parseFloat(tmo) + parseFloat(tm);
                    famt = parseFloat(tmo).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
                    $("#tmodue").text(famt);
                    tms = parseFloat(tms) + parseFloat(kar);
                    famt = parseFloat(tms).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
                    $("#ptspdue").text(famt);
                    
                    volume = parseFloat(volume) + parseFloat(t);
                    famt = parseFloat(volume).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
                    $("#totalvolume").text(famt);
                }
            }



            var time = getDateTimeSpec().slice(0, 10);
            var dat = parseInt(time.slice(8, 10));
            var amt = transactions[i].amount;
            var t = parseFloat(amt);
            var famt = (t).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
            var text = "<article class=\"media event\"><a class=\"pull-left date\"><p class=\"month\">" + getMonth(time) + "</p>" + 
                "<p class=\"day\">" + dat + "</p></a><div class=\"media-body\"><a class=\"title\" href=\"#\">" + setResponseCode(transactions[i].response_code) + "</a>" +
                "<p>" + transactions[i].terminal_id + " - NGN " + famt  + "</p></div></article>";
            if(c <= 10)
                $("#rectrndiv").append(text);
            tt = tt + 1;
            $("#recoveryNum").text(tt);
            if(transactions[i].response_code === "00")
            {
                if(c <= 10)
                    $("#apprtxndiv").append(text);
                ta = ta + 1;
                $("#assetNum").text(ta);
            }else{
                if(c <= 10)
                    $("#declreason").append(text);
                td = td + 1;
                $("#utilityNum").text(td);
            }
        }
    }
}

function getAllOngoing()
{
    $.ajax({
        type: "GET",
        url : "/tms/ongoing/getallongoing",
        processData: false,
        contentType: false,

        success : function(json) {
            if(json === null)
            {
                console.log("Nothing came back... Keep it null");
                return;
            }
            transactions = JSON.parse(json);
            parseTxnResponse();
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
        }
    });
}

function getAllTerminals()
{
    $.ajax({
        type: "GET",
        url : "/tms/transaction/getalltids",
        processData: false,
        contentType: false,

        success : function(json) {
            if(json === null)
            {
                console.log("Nothing came back... Keep it null");
                return;
            }
            tids = JSON.parse(json.message);
            $("#auctionNum").text(tids.length);
            $("#maintendiv").empty();
            $("#recdiv").empty();
            var c = 0;
            var i = tids.length - 1;
            for(; i > -1; i--, c++) {
                var time = tids[i].timestamp.slice(0, 10);
                var dat = time.slice(8, 10);
                var text = "<article class=\"media event\"><a class=\"pull-left date\"><p class=\"month\">" + getMonth(time) + "</p>" + 
                    "<p class=\"day\">" + dat + "</p></a><div class=\"media-body\"><a class=\"title\" href=\"#\">" + tids[i].tid + "</a>" +
                    "<p>" + tids[i].merchantaddress + "</p></div></article>";
                $("#maintendiv").append(text);
                if(tids[i].blocked === "true")
                {
                    $("#recdiv").append(text);
                }
                if(c >= 10)
                    break;
            }
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
        }
    });
}

function proceedPlease()
{
    getAllTerminals();
    getAllStates();
    getAllOngoing();
}

$(document).ready(function() {
    var x = document.getElementById("details").innerText;
    details = JSON.parse(x);
    $("#fullname").text(details.fullname);
    role = details.role;
    console.log(role);
    username = details.username;
    vtmo = details.tmo;
    setInterval(proceedPlease, 3*1000);
});