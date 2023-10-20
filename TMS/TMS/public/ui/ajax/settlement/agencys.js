var role;
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
        url: "/tms/agencysettlement/transactiondetails/" + id,
        async: true,
        dataType: 'json',
        success: function (json) {
            if(json !== null && typeof json !== 'undefined')
            {
                records = json;
                var use = "<p align=\"left\">";
                use += records[0].etranzactresponse + "</br></br></br>";
                use += "TRANSACTION REF: <span style=\"float:right;\">" + records[0].transref + "</span></br>";
                use += "TRANSACTION RRN: <span style=\"float:right;\">" + records[0].ref + "</span></br>";
                use += "TERMINAL ID: <span style=\"float:right;\">" + records[0].tid + "</span></br>";
                use += "TRANSACTION TYPE: <span style=\"float:right;\">" + records[0].transtype + "</span></br>";
                use += "ORIGINAL REF: <span style=\"float:right;\">" + records[0].origtransref + "</span></br>";
                use += "PROCESSOR REF: <span style=\"float:right;\">" + records[0].others + "</span></br>";

                var CDate = new Date(records[0].tousedate.slice(0, 10));
                CDate.setDate(CDate.getDate() + 1);
                
                use += "TRANSACTION DATE: <span style=\"float:right;\">" + CDate.toISOString().substring(0, 10) + "</span></br>";
                //use += "TRANSACTION DATE: <span style=\"float:right;\">" + records[0].tousedate.slice(0, 10) + "</span></br>";
                use += "STATUS: <span style=\"float:right;\">" + records[0].status + "</span></br>";
                
                use += "TOTAL AMOUNT: <span style=\"float:right;\">NGN " + records[0].amount + "</span></br>";
                use += "CLIENT AMOUNT: <span style=\"float:right;\">NGN " + records[0].mainamount + "</span></br>";
                use += "TOTAL FEES: <span style=\"float:right;\">NGN " + records[0].fee + "</span></br>";

                /*if(records[0].transtype === "CASH WITHDRAWAL")
                {
                    var agentamount = (parseFloat(records[0].agentamount) - parseFloat(records[0].mainamount)).toFixed(2);
                    use += "AGENT FEE: <span style=\"float:right;\">NGN " + agentamount + "</span></br>";
                }else*/
                use += "AGENT AMOUNT: <span style=\"float:right;\">NGN " + records[0].agentamount + "</span></br>";
                
                use += "SUPER AGENT FEE: <span style=\"float:right;\">NGN " + records[0].superagentamount + "</span></br>";
                use += "tms FEE: <span style=\"float:right;\">NGN " + records[0].tmsamount + "</span></br>";
                use += "tms VAT: <span style=\"float:right;\">NGN " + records[0].vatkar + "</span></br>";
                use += "MSC: <span style=\"float:right;\">NGN " + records[0].msc + "</span></br>";4
                use += "STAMP DUTY: <span style=\"float:right;\">NGN " + records[0].stampduty + "</span></br>";
                use += "PROCESSOR FEE: <span style=\"float:right;\">NGN " + records[0].switchfee + "</span></br>";
                use += "SUPER SUPER FEE: <span style=\"float:right;\">NGN " + records[0].varetzn + "</span></br>";
                //use += "TO USER: <span style=\"float:right;\">NGN " + records[0].tocustomer + "</span></br>";
                use += "USER CREDENTIAL: <span style=\"float:right;\">" + records[0].destination + "</span></br></br></br>";
                use +=  records[0].etranzactecho + "</br>";

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
var tmsFee = 0.00;
var agentFee = 0.00;
var superagentFee = 0.00;

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
                    url : "/tms/agencysettlement/getbydaterange",
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
                                if(records[i].transtype === "VTU")
                                    continue;
                                if(records[i].transtype === "BILLSPAYMENT")
                                    continue;

                                arr.push(records[i].transtype);
                                arr.push(records[i].tid);
                                arr.push(records[i].ref);
                                arr.push(records[i].transref);
                                var amt = records[i].amount;
                                var t = parseFloat(amt);
                                var famt = (t).toFixed(2);
                                arr.push("NGN " + famt);
                                arr.push(records[i].destination);
                                
                                var CDate = new Date(records[i].tousedate.slice(0, 10));
                                CDate.setDate(CDate.getDate() + 1);
                                arr.push(CDate.toISOString().substring(0, 10));

                                //arr.push(records[i].tousedate.slice(0, 10));
                                arr.push("<button onclick=\"gotoView('" + records[i].id + "');\" type=\"button\" class=\"btn btn-success\">View</button>");
                                if(checkPlease(records[i].tid) === false)
                                {
                                    continue;
                                }

                                if(isNaN(parseFloat(records[i].amount)))
                                    totalAmount = totalAmount + 0.00;
                                else
                                    totalAmount = totalAmount + parseFloat(records[i].amount);

                                if(isNaN(parseFloat(records[i].tmsamount)))
                                    tmsFee = tmsFee + 0.00;
                                else
                                    tmsFee = tmsFee + parseFloat(records[i].tmsamount);

                                if(isNaN(parseFloat(records[i].agentamount)))
                                    agentFee = agentFee + 0.00;
                                else
                                    agentFee = agentFee + parseFloat(records[i].agentamount);

                                if(isNaN(parseFloat(records[i].superagentamount)))
                                    superagentFee = superagentFee + 0.00;
                                else
                                    superagentFee = superagentFee + parseFloat(records[i].superagentamount);
                                
                                var ff = totalAmount.toFixed(2);
                                var sff = "TOTAL TRANSACTION: NGN " + ff;
                                $("#totalAmount").html(sff);

                                if(role === "user")
                                {
                                    ff = tmsFee.toFixed(2);
                                    var sff = "TOTAL tms FEE: NGN " + ff;
                                    $("#tmsFee").html(sff);

                                    ff = agentFee.toFixed(2);
                                    var sff = "TOTAL AGENT FEE: NGN " + ff;
                                    $("#agentFee").html(sff);

                                    ff = superagentFee.toFixed(2);
                                    var sff = "TOTAL SUPER AGENT FEE: NGN " + ff;
                                    $("#superagentFee").html(sff);
                                }else if(role === "agent")
                                {
                                    $("#tmsFee").remove();
                                    $("#superagentFee").remove();
                                    ff = agentFee.toFixed(2);
                                    var sff = "TOTAL AGENT FEE: NGN " + ff;
                                    $("#agentFee").html(sff);
                                }else if(role === "merchant")
                                {
                                    $("#tmsFee").remove();
                                    $("#superagentFee").remove();
                                    ff = agentFee.toFixed(2);
                                    var sff = "TOTAL AGENT FEE: NGN " + ff;
                                    $("#agentFee").html(sff);
                                }else if(role === "super-agent")
                                {
                                    $("#tmsFee").remove();
                                    
                                    ff = agentFee.toFixed(2);
                                    var sff = "TOTAL AGENT FEE: NGN " + ff;
                                    $("#agentFee").html(sff);

                                    ff = superagentFee.toFixed(2);
                                    var sff = "TOTAL SUPER AGENT FEE: NGN " + ff;
                                    $("#superagentFee").html(sff);
                                }
                                if(checkPlease(records[i].tid) === false)
                                {
                                    continue;
                                }
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

function proceedPlease() 
{
    if(tids.length < 1 || uLastId == 0)
    {
        swal(
            'Empty!',
            "No Tid Available....",
            'success'
        );
        return;
    }
	$.ajax({
        url: "/tms/agencysettlement/getAllToday/" + uLastId,
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
                    if(records[i].transtype === "VTU")
                        continue;
                    if(records[i].transtype === "BILLSPAYMENT")
                        continue;
                        
                    arr.push(records[i].transtype);
                    arr.push(records[i].tid);
                    arr.push(records[i].ref);
                    arr.push(records[i].transref);
                    var amt = records[i].amount;
                    var t = parseFloat(amt);
                    var famt = (t).toFixed(2);
                    arr.push("NGN " + famt);
                    arr.push(records[i].destination);

                    var CDate = new Date(records[i].tousedate.slice(0, 10));
                    CDate.setDate(CDate.getDate() + 1);
                    arr.push(CDate.toISOString().substring(0, 10));
                    
                    //arr.push(records[i].tousedate.slice(0, 10));
                    arr.push("<button onclick=\"gotoView('" + records[i].id + "');\" type=\"button\" class=\"btn btn-success\">View</button>");
                    if(checkPlease(records[i].tid) === false)
                    {
                        continue;
                    }

                    if(isNaN(parseFloat(records[i].amount)))
                        totalAmount = totalAmount + 0.00;
                    else
                        totalAmount = totalAmount + parseFloat(records[i].amount);

                    if(isNaN(parseFloat(records[i].tmsamount)))
                        tmsFee = tmsFee + 0.00;
                    else
                        tmsFee = tmsFee + parseFloat(records[i].tmsamount);

                    if(isNaN(parseFloat(records[i].agentamount)))
                        agentFee = agentFee + 0.00;
                    else
                        agentFee = agentFee + parseFloat(records[i].agentamount);

                    if(isNaN(parseFloat(records[i].superagentamount)))
                        superagentFee = superagentFee + 0.00;
                    else
                        superagentFee = superagentFee + parseFloat(records[i].superagentamount);

                    var ff = totalAmount.toFixed(2);
                    var sff = "TOTAL TRANSACTION: NGN " + ff;
                    $("#totalAmount").html(sff);

                    if(role === "user")
                    {
                        ff = tmsFee.toFixed(2);
                        var sff = "TOTAL tms FEE: NGN " + ff;
                        $("#tmsFee").html(sff);

                        ff = agentFee.toFixed(2);
                        var sff = "TOTAL AGENT FEE: NGN " + ff;
                        $("#agentFee").html(sff);

                        ff = superagentFee.toFixed(2);
                        var sff = "TOTAL SUPER AGENT FEE: NGN " + ff;
                        $("#superagentFee").html(sff);
                    }else if(role === "agent")
                    {
                        $("#tmsFee").remove();
                        $("#superagentFee").remove();
                        ff = agentFee.toFixed(2);
                        var sff = "TOTAL AGENT FEE: NGN " + ff;
                        $("#agentFee").html(sff);
                    }else if(role === "merchant")
                    {
                        $("#tmsFee").remove();
                        $("#superagentFee").remove();
                        ff = agentFee.toFixed(2);
                        var sff = "TOTAL AGENT FEE: NGN " + ff;
                        $("#agentFee").html(sff);
                    }else if(role === "super-agent")
                    {
                        $("#tmsFee").remove();

                        ff = agentFee.toFixed(2);
                        var sff = "TOTAL AGENT FEE: NGN " + ff;
                        $("#agentFee").html(sff);

                        ff = superagentFee.toFixed(2);
                        var sff = "TOTAL SUPER AGENT FEE: NGN " + ff;
                        $("#superagentFee").html(sff);
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

            if(records[i].transtype === "VTU")
                continue;
            if(records[i].transtype === "BILLSPAYMENT")
                continue;
                
            arr.push(records[i].transtype);
            arr.push(records[i].tid);
            arr.push(records[i].ref);
            arr.push(records[i].transref);
            var amt = records[i].amount;
            var t = parseFloat(amt);
            var famt = (t).toFixed(2);
            arr.push("NGN " + famt);
            arr.push(records[i].destination);

            var CDate = new Date(records[i].tousedate.slice(0, 10));
            CDate.setDate(CDate.getDate() + 1);
            arr.push(CDate.toISOString().substring(0, 10));
            
            console.log(records[i].tousedate);
            //arr.push(records[i].tousedate.slice(0, 10));
            arr.push("<button onclick=\"gotoView('" + records[i].id + "');\" type=\"button\" class=\"btn btn-success\">View</button>");
            if(checkPlease(records[i].tid) === false)
            {
                continue;
            }
            //Addition here
            //console.log(records[i]);
            if(isNaN(parseFloat(records[i].amount)))
                totalAmount = totalAmount + 0.00;
            else
                totalAmount = totalAmount + parseFloat(records[i].amount);

            if(isNaN(parseFloat(records[i].tmsamount)))
                tmsFee = tmsFee + 0.00;
            else
                tmsFee = tmsFee + parseFloat(records[i].tmsamount);

            if(isNaN(parseFloat(records[i].agentamount)))
                agentFee = agentFee + 0.00;
            else
                agentFee = agentFee + parseFloat(records[i].agentamount);

            if(isNaN(parseFloat(records[i].superagentamount)))
                superagentFee = superagentFee + 0.00;
            else
                superagentFee = superagentFee + parseFloat(records[i].superagentamount);
            /*totalAmount = totalAmount + parseFloat(records[i].amount);
            tmsFee = tmsFee + parseFloat(records[i].tmsamount);
            agentFee = agentFee + parseFloat(records[i].agentamount);
            superagentFee = superagentFee + parseFloat(records[i].superagentamount);*/
            var ff = totalAmount.toFixed(2);
            var sff = "TOTAL TRANSACTION: NGN " + ff;
            $("#totalAmount").html(sff);

            if(role === "user")
            {
                ff = tmsFee.toFixed(2);
                var sff = "TOTAL tms FEE: NGN " + ff;
                $("#tmsFee").html(sff);

                ff = agentFee.toFixed(2);
                var sff = "TOTAL AGENT FEE: NGN " + ff;
                $("#agentFee").html(sff);

                ff = superagentFee.toFixed(2);
                var sff = "TOTAL SUPER AGENT FEE: NGN " + ff;
                $("#superagentFee").html(sff);
            }else if(role === "agent")
            {
                $("#tmsFee").remove();
                $("#superagentFee").remove();
                ff = agentFee.toFixed(2);
                var sff = "TOTAL AGENT FEE: NGN " + ff;
                $("#agentFee").html(sff);
            }else if(role === "merchant")
            {
                $("#tmsFee").remove();
                $("#superagentFee").remove();
                ff = agentFee.toFixed(2);
                var sff = "TOTAL AGENT FEE: NGN " + ff;
                $("#agentFee").html(sff);
            }else if(role === "super-agent")
            {
                $("#tmsFee").remove();
                
                ff = agentFee.toFixed(2);
                var sff = "TOTAL AGENT FEE: NGN " + ff;
                $("#agentFee").html(sff);

                ff = superagentFee.toFixed(2);
                var sff = "TOTAL SUPER AGENT FEE: NGN " + ff;
                $("#superagentFee").html(sff);
            }
            $('#bootstrap-data-table').DataTable().row.add(arr);
        }
        $('#bootstrap-data-table').DataTable().draw();
    }
    //setInterval(proceedPlease, 5*1000);
}

function getAllAgency()
{
    $.ajax({
        type: "GET",
        url : "/tms/agencysettlement/getallagency",
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
        url : "/tms/agencysettlement/getalltids",
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
    username = details.username;
    getAllTerminals();
});