var record;

function gotoRefund(id)
{
    var use = "<p align=\"left\">";
    use += record[id].message + "</br></br></br>";
    use += "REFERENCE: <span style=\"float:right;\">" + record[id].otherreference + "</span></br>";
    use += "RRN: <span style=\"float:right;\">" + record[id].ref + "</span></br>";
    use += "ERROR CODE: <span style=\"float:right;\">" + record[id].errorcode + "</span></br>";
    use += "TID: <span style=\"float:right;\">" + record[id].tid + "</span></br>";
    use += "FULL AMOUNT: <span style=\"float:right;\">" + record[id].fullamount + "</span></br>";
    use += "REFUND AMOUNT: <span style=\"float:right;\">" + record[id].refundamount + "</span></br>";
    use += "BANK NAME: <span style=\"float:right;\">" + record[id].bankname + "</span></br>";
    use += "BANK CODE: <span style=\"float:right;\">" + record[id].bankcode + "</span></br>";
    use += "ACCOUNT NUMBER: <span style=\"float:right;\">" + record[id].accountnumber + "</span></br>";
    use += "STATUS: <span style=\"float:right;\">" + record[id].status + "</span></br>";
    use += "TRANSACTION: <span style=\"float:right;\">" + record[id].transactiontype + "</span></br></br></br>";
    use +=  record[id].fullresponse + "</br>";
    use += "</p>";

    swal({
        title: "Refund?",
        html: use,
        type: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#800080',
        cancelButtonColor: '#001e33',
        confirmButtonText: 'Yes, Retry!'
    }).then(function (result) {
        if (result.value) {
            swal({
                title: "Processing...",
                text: "Please wait",
                showConfirmButton: false,
                allowOutsideClick: false
            });

            var fd = new FormData();
            //fd.append('username', record[id].username);
            $.ajax({
                type: "POST",
                url : "/tms/failedtxns/refund/" + record[id].id,
                data : fd,
                processData: false,
                contentType: false,
        
                success : function(json) {
                    swal(
                        'Done!',
                        record[id].otherreference + " REFUND SUCCESS.",
                        'success'
                    );
                    location.reload();
                },
        
                complete: function(){
                    
                },
                
                error : function(xhr,errmsg,err) {
                    console.log(xhr.responseText);
                    swal(
                        'Error!',
                        record[id].otherreference + " FAILED.",
                        'error'
                    );
                }
            });
        }else
        {

        }
    });
}

function gotoVoid(id)
{
    
    var use = "<p align=\"left\">";
    use += record[id].message + "</br></br></br>";
    use += "REFERENCE: <span style=\"float:right;\">" + record[id].otherreference + "</span></br>";
    use += "RRN: <span style=\"float:right;\">" + record[id].ref + "</span></br>";
    use += "ERROR CODE: <span style=\"float:right;\">" + record[id].errorcode + "</span></br>";
    use += "TID: <span style=\"float:right;\">" + record[id].tid + "</span></br>";
    use += "FULL AMOUNT: <span style=\"float:right;\">" + record[id].fullamount + "</span></br>";
    use += "REFUND AMOUNT: <span style=\"float:right;\">" + record[id].refundamount + "</span></br>";
    use += "BANK NAME: <span style=\"float:right;\">" + record[id].bankname + "</span></br>";
    use += "BANK CODE: <span style=\"float:right;\">" + record[id].bankcode + "</span></br>";
    use += "ACCOUNT NUMBER: <span style=\"float:right;\">" + record[id].accountnumber + "</span></br>";
    use += "STATUS: <span style=\"float:right;\">" + record[id].status + "</span></br>";
    use += "TRANSACTION: <span style=\"float:right;\">" + record[id].transactiontype + "</span></br></br></br>";
    use +=  record[id].fullresponse + "</br>";
    use += "</p>";

    swal({
        title: "Void?",
        html: use,
        type: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#800080',
        cancelButtonColor: '#001e33',
        confirmButtonText: 'Yes, Void!'
    }).then(function (result) {
        if (result.value) {
            swal({
                title: "Processing...",
                text: "Please wait",
                showConfirmButton: false,
                allowOutsideClick: false
            });

            var fd = new FormData();
            $.ajax({
                type: "DELETE",
                url : "/tms/failedtxns/voidtxn/" + record[id].id,
                data : fd,
                processData: false,
                contentType: false,
        
                success : function(json) {
                    swal(
                        'Done!',
                        record[id].otherreference + " VOID SUCCESS.",
                        'success'
                    );
                    location.reload();
                },
        
                complete: function(){
                    
                },
                
                error : function(xhr,errmsg,err) {
                    console.log(xhr.responseText);
                    swal(
                        'Error!',
                        record[id].otherreference + " NOT VOID.",
                        'error'
                    );
                }
            });
        }else
        {

        }
    });
}

function parseResponse()
{
    if(record === null)
    {
        //Do nothing because it is null
        var table = $('#datatable-buttons').DataTable({
                "language": {
                    "emptyTable": "No Data."
                },
                "bDestroy": true
        });
        table.clear().draw();
    }else
    {
        var i = record.length - 1;
        for(; i > -1; i--) {
            arr = [];
            arr.push(record[i].transactiontype);
            arr.push(record[i].ref);
            arr.push(record[i].refundamount);
            arr.push(record[i].message);
            arr.push(record[i].errorcode);
            arr.push(record[i].date.slice(0, 10));
            arr.push("<button onclick=\"gotoRefund('" + i + "');\" type=\"button\" class=\"btn btn-success\">REFUND / RETRY</button>");
            arr.push("<button onclick=\"gotoVoid('" + i + "');\" type=\"button\" class=\"btn btn-success\">VOID</button>");
            $('#datatable-buttons').DataTable().row.add(arr);
        }
        $('#datatable-buttons').DataTable().draw();
    }
}

function getAllData()
{
    $.ajax({
        type: "GET",
        url : "/tms/failedtxns/getalldata",
        processData: false,
        contentType: false,

        success : function(json) {
            record = JSON.parse(json.message);
            parseResponse();
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
    getAllData();
});