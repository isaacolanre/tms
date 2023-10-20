var role;
var username;
var tids;


function formatDt(date) {
    var res = date.replace(" ", "0");
    var dt = res.slice(0, 4) + "-" + res.slice(4, 6) + "-" + res.slice(6, 8) + " " + res.slice(8, 10)
    + "-" + res.slice(10, 12) + "-" + res.slice(12, 14);
    return dt;
}

function formatAmt(amt)
{
    var t = parseFloat(amt);
    var famt = (t).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
    return famt;
}

function getTransactionType(mti, proc)
{
    if(mti === "0200" && proc.slice(0, 2) == "00")
        return "PURCHASE";
    return "UNKNOWN";
}

function getMod(d)
{
    var m = d.length % 2;
    if(m != 0)
        return d + ".";
    else
        return d;
}

function gotoPrint(data)
{
    var index = 0;
    var style = document.createElement('style');
    style.type = 'text/css';
    style.innerHTML = '.swal-wide { width:400px !important; }';
    document.getElementsByTagName('head')[0].appendChild(style);

    var datetime = data.date_trans;
    var dt = "";
    if(datetime.length == 14)
        dt = formatDt(datetime);
    else
        dt = datetime;
    
    var print = "<div id=\"div_print\" style=\"width: 350px;\">";

    var pp = "";
    pp = sprintf("%-12.12s %18.18s", "TERMINAL ID:", data.terminal_id);
    print += "<p align=\"left\">TERMINAL ID: <span style=\"float:right;\">" + data.terminal_id + "</span></br></p>";

    pp = sprintf("%-14.14s %16.16s", "SERIAL NUMBER:", "NOT STORED");
    print += "<p align=\"left\">SERIAL NUMBER: <span style=\"float:right;\">" + "NOT STORED" + "</span></br></p>";

    pp = sprintf("%-12.12s %18.18s", "MERCHANT ID:", data.merchant_id);
    print += "<p align=\"left\">MERCHANT ID: <span style=\"float:right;\">" + data.merchant_id + "</span></br></p>";
    
    pp = "\n..............................";
    print += "<p style=\"text-align: center;\">" + ".....................................................................</br>" + "</p>";
    
    var v = setResponseCode(data.response_code);
    pp = sprintf("   %*s%*s   ", 12 + getMod(v).length / 2, 
        getMod(v), 
        12 - getMod(v).length / 2, "");
    print += "<p style=\"text-align: center;\">" + v.toUpperCase() + "</br></p>";
    
    pp = "\n..............................";
    print += "<p style=\"text-align: center;\">" + ".....................................................................</br>" + "</p>";
    
    pp = sprintf("%-12.12s %18.18s", "TRANSACTION:", getTransactionType(data.mti, data.processing_code));
    print += "<p align=\"left\">TRANSACTION: <span style=\"float:right;\">" + getTransactionType(data.mti, data.processing_code) + "</span></br></p>";
    
    pp = sprintf("%-14.14s %16.16s", "RESPONSE CODE:", data.response_code);
    print += "<p align=\"left\">RESPONSE CODE: <span style=\"float:right;\">" + data.response_code + "</span></br></p>";

    pp = sprintf("%-10.10s %20.20s", "AUTH CODE:", data.auth_code);
    print += "<p align=\"left\">AUTH CODE: <span style=\"float:right;\">" + data.auth_code + "</span></br></p>";

    pp = sprintf("%-5.5s %25.25s", "STAN:", data.stan);
    print += "<p align=\"left\">STAN: <span style=\"float:right;\">" + data.stan + "</span></br></p>";

    pp = sprintf("%-4.4s %26.26s", "RRN:", data.rrn);
    print += "<p align=\"left\">RRN: <span style=\"float:right;\">" + data.rrn + "</span></br></p>";

    pp = sprintf("%-12.12s %18.18s", dt.slice(0, 10), dt.slice(11));
    print += "<p align=\"left\">" + dt.slice(0, 10) + " <span style=\"float:right;\">" + dt.slice(11) + "</span></br></p>";
    

    var amt = data.amount;
    var t = parseFloat(amt);
    var famt = "NGN " + (t).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
    pp = sprintf("%-6.6s %24.24s", "TOTAL:", famt);
    print += "<p align=\"left\">TOTAL: <span style=\"float:right;\">" + famt + "</span></br></p>";

    
    pp = "\n..............................";
    print += "<p style=\"text-align: center;\">" + ".....................................................................</br>" + "</p>";
    
    pp = sprintf("%-4.4s %26.26s", "PAN:", data.masked_pan);
    print += "<p align=\"left\">PAN: <span style=\"float:right;\">" + data.masked_pan + "</span></br></p>";
    
    pp = sprintf("%-12.12s %18.18s", "EXPIRY DATE:", "**/**");
    print += "<p align=\"left\">EXPIRY DATE: <span style=\"float:right;\">" + "**/**" + "</span></br></p>";
    
    if(data.masked_pan === "000000******0000")
    {
        var d = "CASH";
        pp = sprintf("   %*s%*s   ", 12 + d.length / 2, d, 
            12 - d.length / 2, "");
        print += "<p style=\"text-align: center;\">" + d + "</p>";
    }else
    {
        pp = sprintf("%-20.20s %10.10s", "VERIFICATION METHOD:", "PIN");
        print += "<p align=\"left\">VERIFICATION METHOD: <span style=\"float:right;\">" + "PIN" + "</span></br></p>";
    }

    pp = "\n..............................";
    print += "<p style=\"text-align: center;\">" + ".....................................................................</br>" + "</p>";
    
    pp = sprintf("%-15.15s %15.15s", "PRINTER NUMBER:", "****");
    print += "<p align=\"left\">PRINTER NUMBER: <span style=\"float:right;\">" + "****" + "</span></br></p>";
    
     
    pp = sprintf("%-8.8s %22.22s", "VERSION:", "NOT STORED");
    print += "<p align=\"left\">VERSION: <span style=\"float:right;\">" + "NOT STORED" + "</span></br></p>";
    
    pp = "\n..............................";
    print += "<p style=\"text-align: center;\">" + ".....................................................................</br>" + "</p>";
    
    var d = "PTSP: ***** ";
    pp = sprintf("   %*s%*s   ", 12 + d.length / 2, d, 
        12 - d.length / 2, "");
    print += "<p style=\"text-align: center;\">" + d + "</p>";
    
    pp = sprintf("   %*s%*s   ", 12 + "Powerred by TMS.. ".length / 2, "Powerred by TMS.. ", 
        12 - "Powerred by TMS.. ".length / 2, "");
    print += "<p style=\"text-align: center;\">" + "Powerred by TMS.. " + "</p>";
    
    pp = sprintf("   %*s%*s   ", 12 + "tms COPY. ".length / 2, "tms COPY. ", 
        12 - "tms COPY. ".length / 2, "");
    print += "<p style=\"text-align: center;\">" + "tms COPY. " + "</p>";

    if(data.extras)
    {
        print += "<p style=\"text-align: center;\">" + "=============================</br>" + "</p>";
        print += "<p style=\"text-align: center;\">" + "PAYMENT DETAILS" + "</p>";
        print += "<p style=\"text-align: center;\">" + "=============================</br>" + "</p>";
        var store = "";
        for(var m = 0; m < data.extras.length; m++)
        {
            if(data.extras.charAt(m) === '.')
                store = store + "</br>";
            else if(data.extras.charAt(m) === '=')
                store = store + ": ";
            else
                store = store + data.extras.charAt(m);
            
        }
        print += "<p style=\"text-align: center;\">" + store + "</p>";
    }

    pp = "\n..............................";
    print += "<p style=\"text-align: center;\">" + ".....................................................................</br>" + "</p>";
    
    print += "</div>";
    swal({
        title: 'REPRINT',
        text: "LOVE",
        html: print,
        type: "success",
        customClass: 'swal-wide',
        showCancelButton: false,
        showConfirmButton:true
    });

    var printWindow = window.open();
    printWindow.document.open('text/plain')
    
    printWindow.document.write(document.getElementById('div_print').innerHTML);

    printWindow.document.close();
    printWindow.focus();
    printWindow.print();
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

var records;
var startdate = "";
var enddate = "";

function getMonth(mnth)
{
  if(mnth.indexOf("Jan") !== -1)
  {
    return "01";
  }else if(mnth.indexOf("Feb") !== -1)
  {
    return "02";
  }else if(mnth.indexOf("Mar") !== -1)
  {
    return "03";
  }else if(mnth.indexOf("Apr") !== -1)
  {
    return "04";
  }else if(mnth.indexOf("May") !== -1)
  {
    return "05";
  }else if(mnth.indexOf("Jun") !== -1)
  {
    return "06";
  }else if(mnth.indexOf("Jul") !== -1)
  {
    return "07";
  }else if(mnth.indexOf("Aug") !== -1)
  {
    return "08";
  }else if(mnth.indexOf("Sep") !== -1)
  {
    return "09";
  }else if(mnth.indexOf("Oct") !== -1)
  {
    return "10";
  }else if(mnth.indexOf("Nov") !== -1)
  {
    return "11";
  }else if(mnth.indexOf("Dec") !== -1)
  {
    return "12";
  }else
  {
    return "01";
  }
}

function getDay(day)
{
    if(parseInt(day) < 10)
        return "0" + parseInt(day);
    return day;
}

function calculateDateRange()
{
    var str = $("#Select_date").text();
    if(str.indexOf("-") !== -1)
    {
        var chr = str.indexOf(" - ");
        var year = new Date().getFullYear();
        var realDate = $("#Select_date").text();
        var month = getMonth(realDate.slice(0, 3));
        var day = getDay(realDate.slice(4, chr));
        startdate = year + "-" + month + "-" + day;
        month = getMonth(realDate.slice(chr + 3, chr + 3 + 3));
        day = getDay(realDate.slice(chr + 3 + 4));
        enddate = year + "-" + month + "-" + day;
    }else
    {
        var year = new Date().getFullYear();
        var realDate = $("#Select_date").text();
        var month = getMonth(realDate.slice(0, 3));
        var day = getDay(realDate.slice(4));
        startdate = year + "-" + month + "-" + day;
        enddate = startdate;
    }
    
    // console.log(startdate);
    // console.log(enddate);
    
    var table = $('#datatable-buttons').DataTable({
        "language": {
            "emptyTable": "No Records"
        },
        "bDestroy": true
    });

    table.destroy();

    var table = $('#datatable-buttons').DataTable( {
        "scrollX": true,
        "fnRowCallback": function (nRow, aData, iDisplayIndex) {
            // Bind click event
            $(nRow).click(function() {
                displayParticularData(aData);
            });
            return nRow;
        },
        dom: 'Bfrltip',
        buttons: [
            'copy', 'csv', 'excel', 'pdf', 'print'
        ],
        "ajax": {
            "url": "/tms/ejournal/getalltransaction/" + startdate + "/" + enddate,
            "dataSrc": "",
        },
        "columns": [
            { "data": "id" },
            { "data": "username" },
            { "data": "amount" },
            { "data": "terminal_id" },
            { "data": "masked_pan" },
            { "data": "rrn" },
            { "data": "response_code" },
            { "data": "original_rrn" },
            { "data": "auth_code" },
            { "data": "card_expiry" },
            { "data": "stan" },
            { "data": "mid" },
            { "data": "tap" },
            { "data": "current_timestamp" },
        ]
    });
}

function displayParticularData(data)
{
    var use = "<p align=\"left\">";
    for (var key in data) {
        use += key.toUpperCase() 
            + ": <span style=\"float:right;\">" 
            + data[key] + "</span></br>";
    }
    use += "</p>";

    swal({
        title: 'Details',
        html: use,
        type: 'success',
        showCancelButton: true,
        confirmButtonColor: '#800080',
        cancelButtonColor: '#001e33',
        confirmButtonText: 'Print'
    }).then(function (result) {
        if (result.value) 
        {
            gotoPrint(data);
        }else
        {

        }
    });
    //swal("Transaction Details!", use, "success");
}

$("#table_refresh a").click(function () {
    calculateDateRange();
});

$(document).ready(function() {
    calculateDateRange();
});