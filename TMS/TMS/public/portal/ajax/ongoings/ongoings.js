var role;
var username;
var tids;
var records;
var uLastId = 0;

function checkPlease(value)
{
    for(var i=0; i<tids.length; i++){
        if(tids[i].tid === value){
            return true;
        }
    }
    return false;
}

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

$("#filterTxn").click(function(e)
{
    if(tids.length < 1)
    {
        swal(
            'Empty!',
            "No Tid Available....",
            'success'
        );
        return;
    }

    var use = "<div class=\"form-group\">"
    use += "<label for=\"cc-payment\" class=\"control-label mb-1\" style=\"float:left;\">Start Date</label>";
    use += "<input id=\"startdate\" name=\"cc-payment\" type=\"text\" class=\"form-control\" aria-required=\"true\" aria-invalid=\"false\" maxlength=\"50\" value=\"\" placeholder=\"YYYY-MM-DD\">";
    use += "</div>"

    use += "<div class=\"form-group\">"
    use += "<label for=\"cc-payment\" class=\"control-label mb-1\" style=\"float:left;\">End Date</label>";
    use += "<input id=\"enddate\" name=\"cc-payment\" type=\"text\" class=\"form-control\" aria-required=\"true\" aria-invalid=\"false\" maxlength=\"50\" value=\"\" placeholder=\"YYYY-MM-DD\">";
    use += "</div>"

    swal({
        title: 'Query',
        html: use,
        type: 'success',
        showCancelButton: true,
        confirmButtonColor: '#800080',
        cancelButtonColor: '#001e33',
        confirmButtonText: 'Search and Export'
    }).then(function (result) {
        if (result.value) {
            var sd = $("#startdate").val();
            var ed = $("#enddate").val();
            if(sd.length < 1 || ed.length < 1)
            {
                swal(
                    'Error',
                    'Invalid Search Parameters',
                    'error'
                );
            }else
            {
                $("#filterTxn").text("Fetching. Please Wait");
                $("#filterTxn").prop("disabled",true);
                var fd = new FormData();
                fd.append('sd', sd);
                fd.append('ed', ed);

                $.ajax({
                    type: "POST",
                    url : "/tms/ongoing/getbydaterange",
                    data : fd,
                    processData: false,
                    contentType: false,
                    
                    success : function(json) {
                        $("#filterTxn").text("Filter Transaction");
                        $("#filterTxn").prop("disabled",false);
                        window.location.href = "/downloads/" + json;
                    },

                    complete: function(){
                        $("#filterTxn").text("Filter Transaction");
                        $("#filterTxn").prop("disabled",false);
                    },
                    
                    error : function(xhr,errmsg,err) {
                        var json = JSON.parse(xhr.responseText);
                        swal(
                            'Error!',
                            "Query Error.",
                            'error'
                        );
                    }
                });
            }
        }else
        {

        }
    });
});

$("#exportbutton").click(function(e){
    $("#exportbutton").text("Please Wait");
    $("#exportbutton").prop("disabled",true);
    var table = $('#bootstrap-data-table').DataTable();
    //var data = table.rows({filter: 'applied'}).data();
    const data = records;
    const fileName = 'transactions'
    const exportType = 'csv'
    window.exportFromJSON({ data, fileName, exportType});
    $("#exportbutton").text("Please Reload Page");
    $("#exportbutton").prop("disabled",false);
});

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

function proceedPlease() 
{
    if(tids.length < 1)
    {
        swal(
            'Empty!',
            "No Tid Available....",
            'success'
        );
        return;
    }
	$.ajax({
        url: "/tms/ongoing/getAllToday/" + uLastId,
        async: true,
        dataType: 'json',
        success: function (json) {
            if(json !== null && typeof json !== 'undefined')
            {
                records = json;
                var arr = [];
                var t = $('#bootstrap-data-table').DataTable();
                for(var i = 0; i < records.length; i++)
                {
                    var lastId = records[i].id;
                    if(lastId > uLastId)
                        uLastId = lastId;
                    if(role !== "user")
                    {
                        var j = 0;
                        var m = tids.length - 1;
                        for(; m > -1; m--) {
                            if(tids[m].tid === records[i].terminal_id)
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
                    arr = [];
                    arr.push(records[i].terminal_id);
                    arr.push(setResponseCode(records[i].response_code));
                    arr.push(records[i].masked_pan);
                    if(records[i].auth_code) 
                        arr.push(records[i].auth_code);
                    else
                        arr.push("NA");
                    var amt = records[i].amount;
                    var t = parseFloat(amt);
                    var famt = (t).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
                    arr.push("NGN " + famt);
                    arr.push(records[i].tap);
                    var datetime = records[i].date_trans;
                    var dt = "";
                    if(datetime.length == 14)
                        dt = formatDt(datetime);
                    else
                        dt = datetime;
                    arr.push(dt);
                    if(checkPlease(records[i].terminal_id) === false)
                    {
                        //console.log("Nothing found")
                        continue;
                    }
                    $('#bootstrap-data-table').DataTable().row.add(arr).draw(false);
                    $('#bootstrap-data-table').DataTable().page('last').draw('page');
                    $('#bootstrap-data-table').css("width", "100%");
                }
            }
        },
        complete: function(){
            
        },
        error : function(xhr,errmsg,err) {
            //location.reload();
        }
    });

}

function parseResponse()
{
    if(tids.length < 1)
    {
        swal(
            'Empty!',
            "No Tid Available....",
            'success'
        );
        return;
    }

    if(records === null)
    {
        //Do nothing because it is null
        var table = $('#bootstrap-data-table').DataTable({
                "language": {
                    "emptyTable": "No Data."
                },
                "bDestroy": true
        });
        table.clear().draw();
    }else
    {
        var i = records.length - 1;
        for(; i > -1; i--) {
            var lastId = records[i].id;
			if(lastId > uLastId)
				uLastId = lastId;
            if(role !== "user")
            {
                var j = 0;
                var m = tids.length - 1;
                for(; m > -1; m--) {
                    if(tids[m].tid === records[i].terminal_id)
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
            arr = [];
            arr.push(records[i].terminal_id);
            arr.push(setResponseCode(records[i].response_code));
            arr.push(records[i].masked_pan);
            if(records[i].auth_code) 
                arr.push(records[i].auth_code);
            else
                arr.push("NA");
            var amt = records[i].amount;
            var t = parseFloat(amt);
            var famt = (t).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
            arr.push("NGN " + famt);
            arr.push(records[i].tap);
            var datetime = records[i].date_trans;
            var dt = "";
            if(datetime.length == 14)
                dt = formatDt(datetime);
            else
                dt = datetime;
            arr.push(dt);
            if(checkPlease(records[i].terminal_id) === false)
            {
                //console.log("Nothing found")
                continue;
            }
            $('#bootstrap-data-table').DataTable().row.add(arr);
        }
        $('#bootstrap-data-table').DataTable().draw();
    }
    setInterval(proceedPlease, 5*1000);
}

function getAllOngoing()
{
    $.ajax({
        type: "GET",
        url : "/tms/ongoing/getallongoing",
        processData: false,
        contentType: false,

        success : function(json) {
            if(json !== null && typeof json !== 'undefined')
            {
                records = JSON.parse(json);
                parseResponse();
            }
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
        url : "/tms/ongoing/getalltids",
        processData: false,
        contentType: false,

        success : function(json) {
            tids = JSON.parse(json.message);
            getAllOngoing();
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
        }
    });
}

$(document).ready(function() {
    $("#tmsform").hide();
    var x = document.getElementById("details").innerText;
    details = JSON.parse(x);
    $("#fullname").text(details.fullname);
    role = details.role;
    username = details.username;
    $('#bootstrap-data-table').DataTable({
        "createdRow": function( row, data, dataIndex ) {
            if (data[1] === "Approved.." ) {
                $(row).addClass( 'green' );
            }else if(data[1] === "Could Not Connect" ||
                data[1] === "No Response From Nibss" || 
                data[1] === "No Response From Nibss")
            {
                $(row).addClass( 'red' );
            }else
            {
                $(row).addClass( 'brown' );
            }
        }
    });
    getAllTerminals();
});