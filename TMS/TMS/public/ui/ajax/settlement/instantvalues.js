var role;
var usertype;
var username;
var tids;
var records;
var uLastId = 0;

function checkPlease(value)
{
    if(role === "user")
        return true;
    {
        for(var i=0; i<tids.length; i++){
            if(tids[i].tid === value){
                return true;
            }
        }
        return false;
    }
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
    var famt = (t).toFixed(2);
    return famt;
}

$("#exportbutton").click(function(e){
    $("#exportbutton").text("Please Wait");
    $("#exportbutton").prop("disabled",true);
    var table = $('#bootstrap-data-table').DataTable();
    var data = table.rows({filter: 'applied'}).data();
    var exp = [];
    for(var i = 0; i < data.length; i++)
    {
        exp.push(records[i]);
    }
    var myTestXML = new myExcelXML(JSON.stringify(exp));
    myTestXML.downLoad();
    $("#exportbutton").text("Please Reload Page");
    $("#exportbutton").prop("disabled",false);
});

function gotoView(id)
{
    $.ajax({
        url: "/tms/instantvalue/transactiondetails/" + id,
        async: true,
        dataType: 'json',
        success: function (json) {
            if(json !== null && typeof json !== 'undefined')
            {
                records = json;
                var use = "<p align=\"left\">";
                use += "TID: <span style=\"float:right;\">" + records[0].tid + "</span></br>";
                use += "MID: <span style=\"float:right;\">" + records[0].mid + "</span></br>";
                use += "AMOUNT: <span style=\"float:right;\">" + records[0].amount + "</span></br>";
                if(records[0].msc === "" || records[0].msc === "NA" || records[0].msc === null)
                    use += "MSC: <span style=\"float:right;\">" + "0.5" + "</span></br>";                    
                else
                    use += "MSC: <span style=\"float:right;\">" + records[0].msc + "</span></br>";
                if(parseFloat(records[0].amount) < 10000)
                {
                    use += "STAMP DUTY: <span style=\"float:right;\">" + "0.00" + "</span></br>";
                }else
                {
                    use += "STAMP DUTY: <span style=\"float:right;\">" + records[0].stampduty + "</span></br>";
                }
                if(records[0].instantvaluepercentage === "" || records[0].instantvaluepercentage === "NA" || records[0].instantvaluepercentage === null)
                    use += "INSTANT VALUE: <span style=\"float:right;\">" + "0.9" + "</span></br>";
                else
                    use += "INSTANT VALUE: <span style=\"float:right;\">" + records[0].instantvaluepercentage + "</span></br>";
                use += "TIME DUE SETTLEMENT: <span style=\"float:right;\">" + records[0].instantvaluetime + "</span></br>";
                //use += "TRANSACTION TIME: <span style=\"float:right;\">" + records[0].startdate + "</span></br>";
                use += "TYPE: <span style=\"float:right;\">" + records[0].transtype + "</span></br>";
                use += "ACCOUNT NAME: <span style=\"float:right;\">" + records[0].accountname + "</span></br>";
                use += "BANK CODE: <span style=\"float:right;\">" + records[0].accountbankcode + "</span></br>";
                use += "ACCOUNT NUMBER: <span style=\"float:right;\">" + records[0].accountnumber + "</span></br>";
                use += "BANK NAME: <span style=\"float:right;\">" + records[0].bankname + "</span></br>";
                use += "STATUS: <span style=\"float:right;\">" + records[0].status + "</span></br>";
                use += "LAST ATTEMPT: <span style=\"float:right;\">" + records[0].lastretry + "</span></br>";
                use += "</p>";
                swal("Transaction Details!", use, "success");  
            }
        },
        complete: function(){
            
        },
        error : function(xhr,errmsg,err) {
            //location.reload();
        }
    });
}

var totalAmount = 0.00;

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
        confirmButtonText: 'Search'
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
                    url : "/tms/instantvalue/getbydaterange",
                    data : fd,
                    processData: false,
                    contentType: false,
                    
                    success : function(json) {
                        $("#filterTxn").text("Filter Transaction");
                        $("#filterTxn").prop("disabled",false);
                        var records = JSON.parse(json);
                        var arr = [];
                        if(records !== null && typeof records !== 'undefined')
                        {
                            var table = $('#bootstrap-data-table').DataTable({
                                    "language": {
                                        "emptyTable": "No Data."
                                    },
                                    "bDestroy": true
                            });
                            table.clear().draw();
                            var bt = $('#bootstrap-data-table').DataTable();
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
                                        if(tids[m].tid === records[i].tid)
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

                                arr.push(records[i].tid);
                                arr.push(records[i].amount);
                                var amt = records[i].amount;
                                var t = parseFloat(amt);
                                var smsc = 0.0;
                                if(records[i].msc === "" || records[i].msc === "NA" || records[i].msc === null)
                                    smsc = 0.5;
                                else
                                    smsc = records[i].msc;
                                var msc = ((smsc/100) * t).toFixed(2);
                                if(msc > 1000)
                                    msc = 1000;
                                var sinv = 0.0;
                                if(records[i].instantvaluepercentage === "" || records[i].instantvaluepercentage === "NA" || records[i].instantvaluepercentage === null)
                                    sinv = 0.9;
                                else
                                    sinv = records[i].instantvaluepercentage;
                                
                                var stamp = 0.00;
                                if(parseFloat(records[i].amount) >= 10000)
                                    stamp = parseFloat(records[i].stampduty);
                                
                                var iv = ((sinv/100) * t).toFixed(2);
                                var amount = parseFloat(amt) - parseFloat(msc) - parseFloat(iv) - stamp;
                                arr.push(amount);
                                arr.push(smsc);
                                arr.push(sinv);
                                arr.push(stamp);
                                arr.push(records[i].status);
                                arr.push(records[i].lastretry);
                                arr.push("<button onclick=\"gotoView('" + records[i].id + "');\" type=\"button\" class=\"btn btn-success\">View</button>");
                                
                                
                                if(role === "user")
                                {
                                    if(usertype === "maker")
                                    {
                                        if(records[i].status === "NOT SETTLED" && records[i].makername === null)
                                        {
                                            arr.push("NA");
                                        }else
                                        {
                                            arr.push("MAKER APPROVE BY: " + records[i].makername);
                                        }                    
                                    }else
                                    {
                                        if(records[i].status === "NOT SETTLED" && records[i].checkername === null)
                                        {
                                            arr.push("NA");
                                            arr.push("NA");
                                        }else
                                        {
                                            arr.push("CHECKER APPROVE BY: " + records[i].checkername);
                                            arr.push("RETRIED BY: " + records[i].checkerretryname);
                                        }    
                                    }
                                }
                                
                                if(checkPlease(records[i].tid) === false)
                                {
                                    continue;
                                }
                                totalAmount = totalAmount + parseFloat(iv);
                                var sff = "TOTAL INSTANT VALUE: NGN " + totalAmount.toFixed(2);
                                if(role === "user")
                                {
                                    $("#tiv").html(sff);
                                }else
                                    $("#tiv").hide();
                                    
                                bt.row.add( arr ).draw( false );
                                $('#bootstrap-data-table').DataTable().page('last').draw('page');
                                $('#bootstrap-data-table').css("width", "100%");
                            }
                        }
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

function makerApproval(id)
{
    swal({
        title: 'MAKER APPROVAL',
        text: "Are you sure you want to approval this payment? There is no Reversal for this Action.",
		type: 'info',
        showCancelButton: true,
        confirmButtonColor: '#800080',
        cancelButtonColor: '#001e33',
        confirmButtonText: 'Proceed'
    }).then(function (result) {
		if (result.value) 
		{
            $.ajax({
                url : "/tms/instantvalue/makerapproval/" + id,
				async: true,
				dataType: 'json',
                
                success : function(json) {
                    swal({
                        title: "Processing.....!",
                        showConfirmButton: false,
                        timer: 1000
                    });
                    if(json.status == 200)
                    {
                        location.reload();
                    }
                },
        
                complete: function(){
                    
                },
                
                error : function(xhr,errmsg,err) {
                    var json = JSON.parse(xhr.responseText);
                    swal(
                        'Error!',
                        "An Error Occured.",
                        'error'
                    );
                }
            });
        }else
        {
            
        }
    });
}

function checkerApproval(id)
{
    swal({
        title: 'MAKER APPROVAL',
        text: "Are you sure you want to approval this payment? There is no Reversal for this Action.",
		type: 'info',
        showCancelButton: true,
        confirmButtonColor: '#800080',
        cancelButtonColor: '#001e33',
        confirmButtonText: 'Proceed'
    }).then(function (result) {
		if (result.value) 
		{
            $.ajax({
                url : "/tms/instantvalue/checkerapproval/" + id,
				async: true,
				dataType: 'json',
                
                success : function(json) {
                    swal({
                        title: "Processing.....!",
                        showConfirmButton: false,
                        timer: 1000
                    });
                    if(json.status == 200)
                    {
                        location.reload();
                    }
                },
        
                complete: function(){
                    
                },
                
                error : function(xhr,errmsg,err) {
                    var json = JSON.parse(xhr.responseText);
                    swal(
                        'Error!',
                        "An Error Occured.",
                        'error'
                    );
                }
            });
        }else
        {
            
        }
    });
}

function proceedPlease() 
{
    if(tids.length < 1 || uLastId < 1)
    {
        swal(
            'Empty!',
            "No Tid Available....",
            'success'
        );
        return;
    }
	$.ajax({
        url: "/tms/instantvalue/getAllToday/" + uLastId,
        async: true,
        dataType: 'json',
        success: function (json) {
            if(json !== null && typeof json !== 'undefined')
            {
                records = json;
                var arr = [];
                var t = $('#bootstrap-data-table').DataTable();
                console.log(records);
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
                            if(tids[m].tid === records[i].tid)
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
                    
                    arr.push(records[i].tid);
                    arr.push(records[i].amount);
                    var amt = records[i].amount;
                    var t = parseFloat(amt);

                    var smsc = 0.0;
                    if(records[i].msc === "" || records[i].msc === "NA" || records[i].msc === null)
                        smsc = 0.5;
                    else
                        smsc = records[i].msc;
                    var msc = ((smsc/100) * t).toFixed(2);
                    if(msc > 1000)
                        msc = 1000;
                    var sinv = 0.0;
                    if(records[i].instantvaluepercentage === "" || records[i].instantvaluepercentage === "NA" || records[i].instantvaluepercentage === null)
                        sinv = 0.9;
                    else
                        sinv = records[i].instantvaluepercentage;
                        
                    var stamp = 0.00;
                    if(parseFloat(records[i].amount) >= 10000)
                        stamp = parseFloat(records[i].stampduty);
                    
                    var iv = ((sinv/100) * t).toFixed(2);
                    var amount = parseFloat(amt) - parseFloat(msc) - parseFloat(iv) - stamp;
                    arr.push(amount);
                    arr.push(smsc);
                    arr.push(sinv);
                    arr.push(stamp);
                    arr.push(records[i].status);
                    arr.push(records[i].lastretry);
                    arr.push("<button onclick=\"gotoView('" + records[i].id + "');\" type=\"button\" class=\"btn btn-success\">View</button>");
                    
                    if(role === "user")
                    {
                        if(usertype === "maker")
                        {
                            if(records[i].status === "NOT SETTLED" && records[i].makername === null)
                            {
                                arr.push("<button onclick=\"makerApproval('" + records[i].id + "');\" type=\"button\" class=\"btn btn-success\">Maker Approval</button>");
                            }else
                            {
                                arr.push("MAKER APPROVE BY: " + records[i].makername);
                            }                    
                        }else
                        {
                            if(records[i].status === "NOT SETTLED" && records[i].checkername === null)
                            {
                                arr.push("<button onclick=\"checkerApproval('" + records[i].id + "');\" type=\"button\" class=\"btn btn-success\">Checker Approval</button>");
                            }else
                            {
                                arr.push("CHECKER APPROVE BY: " + records[i].checkername);
                            }    
                        }
                    }

                    if(checkPlease(records[i].tid) === false)
                    {
                        continue;
                    }
                    totalAmount = totalAmount + parseFloat(iv);
                    var sff = "TOTAL INSTANT VALUE: NGN " + totalAmount.toFixed(2);
                    if(role === "user")
                    {
                        $("#tiv").html(sff);
                    }else
                        $("#tiv").hide();
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
                    if(tids[m].tid === records[i].tid)
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

            arr.push(records[i].tid);
            arr.push(records[i].amount);
            var amt = records[i].amount;
            var t = parseFloat(amt);
            var smsc = 0.0;
            if(records[i].msc === "" || records[i].msc === "NA" || records[i].msc === null)
                smsc = 0.5;
            else
                smsc = records[i].msc;
            var msc = ((smsc/100) * t).toFixed(2);
            if(msc > 1000)
                msc = 1000;
            var sinv = 0.0;
            if(records[i].instantvaluepercentage === "" || records[i].instantvaluepercentage === "NA" || records[i].instantvaluepercentage === null)
                sinv = 0.9;
            else
                sinv = records[i].instantvaluepercentage;

            var stamp = 0.00;
            if(parseFloat(records[i].amount) >= 10000)
                stamp = parseFloat(records[i].stampduty);
                
            var iv = ((sinv/100) * t).toFixed(2);
            var amount = parseFloat(amt) - parseFloat(msc) - parseFloat(iv) - stamp;
            arr.push(amount);
            arr.push(smsc);
            arr.push(sinv);
            arr.push(stamp);
            arr.push(records[i].status);
            arr.push(records[i].lastretry);
            arr.push("<button onclick=\"gotoView('" + records[i].id + "');\" type=\"button\" class=\"btn btn-success\">View</button>");
            
            if(role === "user")
            {
                if(usertype === "maker")
                {
                    if(records[i].status === "NOT SETTLED" && records[i].makername === null)
                    {
                        arr.push("<button onclick=\"makerApproval('" + records[i].id + "');\" type=\"button\" class=\"btn btn-success\">Maker Approval</button>");
                    }else
                    {
                        arr.push("MAKER APPROVE BY: " + records[i].makername);
                    }                    
                }else
                {
                    if(records[i].status === "NOT SETTLED" && records[i].checkername === null)
                    {
                        arr.push("<button onclick=\"checkerApproval('" + records[i].id + "');\" type=\"button\" class=\"btn btn-success\">Checker Approval</button>");
                    }else
                    {
                        arr.push("CHECKER APPROVE BY: " + records[i].checkername);
                    }    
                }
            }
            
            if(checkPlease(records[i].tid) === false)
            {
                continue;
            }
            totalAmount = totalAmount + parseFloat(iv);
            var sff = "TOTAL INSTANT VALUE: NGN " + totalAmount.toFixed(2);
            if(role === "user")
            {
                $("#tiv").html(sff);
            }else
                $("#tiv").hide();
            $('#bootstrap-data-table').DataTable().row.add(arr);
        }
        $('#bootstrap-data-table').DataTable().draw();
    }
}

function getAllAgency()
{
    $.ajax({
        type: "GET",
        url : "/tms/instantvalue/getallinstantvalue",
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
        url : "/tms/instantvalue/getalltids",
        processData: false,
        contentType: false,

        success : function(json) {
            tids = JSON.parse(json.message);
            getAllAgency();
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
    usertype = details.usertype;
    username = details.username;
    getAllTerminals();
});