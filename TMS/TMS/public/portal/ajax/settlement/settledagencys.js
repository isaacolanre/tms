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


function gotoView(id)
{
    $.ajax({
        url: "/tms/settledagency/transactiondetails/" + id,
        async: true,
        dataType: 'json',
        success: function (json) {
            if(json !== null && typeof json !== 'undefined')
            {
                records = json;
                var use = "<p align=\"left\">";
                use += "TID: <span style=\"float:right;\">" + records[0].tid + "</span></br>";
                use += "RRN: <span style=\"float:right;\">" + records[0].ref + "</span></br>";
                use += "AMOUNT: <span style=\"float:right;\">" + records[0].amount + "</span></br>";
                use += "ACCOUNT NAME: <span style=\"float:right;\">" + records[0].accountname + "</span></br>";
                use += "BANK CODE: <span style=\"float:right;\">" + records[0].bankcode + "</span></br>";
                use += "ACCOUNT NUMBER: <span style=\"float:right;\">" + records[0].accountnumber + "</span></br>";
                use += "BANK NAME: <span style=\"float:right;\">" + records[0].bankname + "</span></br>";
                use += "REFERENCE: <span style=\"float:right;\">" + records[0].reference + "</span></br>";
                use += "</p>";
                swal("Settlement Details!", use, "success");  
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
                    url : "/tms/settledagency/getbydaterange",
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
                                arr.push(records[i].ref);
                                arr.push(records[i].amount);
                                arr.push(records[i].bankname);
                                arr.push(records[i].accountname);
                                arr.push(records[i].accountnumber);
                                arr.push(records[i].bankcode);
                                arr.push("<button onclick=\"gotoView('" + records[i].id + "');\" type=\"button\" class=\"btn btn-success\">View</button>");
                                
                                if(checkPlease(records[i].tid) === false)
                                {
                                    continue;
                                }
                                totalAmount = totalAmount + parseFloat(records[i].amount);
                                var sff = "TOTAL SETTLED VALUE: NGN " + totalAmount.toFixed(2);
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
            arr.push(records[i].ref);
            arr.push(records[i].amount);
            arr.push(records[i].bankname);
            arr.push(records[i].accountname);
            arr.push(records[i].accountnumber);
            arr.push(records[i].bankcode);
            arr.push("<button onclick=\"gotoView('" + records[i].id + "');\" type=\"button\" class=\"btn btn-success\">View</button>");
            
            if(checkPlease(records[i].tid) === false)
            {
                continue;
            }
            totalAmount = totalAmount + parseFloat(records[i].amount);
            var sff = "TOTAL SETTLED VALUE: NGN " + totalAmount.toFixed(2);
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
        url : "/tms/settledagency/getallsettlement",
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
        url : "/tms/settledagency/getalltids",
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