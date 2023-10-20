var record;
var edit = false;
var gId = 0;
var pending = null;

function gotoApprove(id)
{
    var use = "<p align=\"left\">";
    use += "EMAIL: <span style=\"float:right;\">" + pending[id].email + "</span></br>";
    use += "AMOUNT: <span style=\"float:right;\"> NGN" + pending[id].amount + "</span></br>";
    use += "INITIATED BY: <span style=\"float:right;\">" + pending[id].initiator + "</span></br>";
    use += "TIME INITIATED: <span style=\"float:right;\">" + pending[id].timeinitiated + "</span></br>";
    //end
    use += "</p>";
    
    swal({
        title: "Approve or Delete?",
        html: use,
        //text: use,
        type: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#800080',
        cancelButtonColor: '#001e33',
        confirmButtonText: 'Yes, Approve!',
        confirmButtonClass: "btn-danger",
        cancelButtonText: "No, Revoke!",
        allowOutsideClick: "true" 
    }).then(function (result) {
        if (result.value) {
            swal({
                title: "Processing...",
                text: "Please wait",
                showConfirmButton: false,
                allowOutsideClick: false
            });
            var fd = new FormData();
            fd.append('email', pending[id].email);
            fd.append('amount', pending[id].amount);
            $.ajax({
                type: "PUT",
                url : "/tms/credits/update/" + pending[id].id,
                data : fd,
                processData: false,
                contentType: false,
        
                success : function(json) {
                    swal(
                        'Done!',
                        "Wallet Funded ....",
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
                        "Error Occurred",
                        'error'
                    );
                }
            });
        }else
        {
            swal({
                title: "Processing...",
                text: "Please wait",
                showConfirmButton: false,
                allowOutsideClick: false
            });
            var fd = new FormData();
            $.ajax({
                type: "DELETE",
                url : "/tms/credits/deletedata/" + pending[id].id,
                data : fd,
                processData: false,
                contentType: false,
        
                success : function(json) {
                    swal(
                        'Done!',
                        "Changes Declined....",
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
                        "Error Occurred",
                        'error'
                    );
                }
            });
        }
    });
}

function parseResponse()
{
    if(pending === null)
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
        var i = pending.length - 1;
        for(; i > -1; i--) {
            arr = [];

            arr.push(pending[i].email);
            arr.push(pending[i].amount);
            arr.push(pending[i].initiator);
            arr.push(pending[i].timeinitiated);
            arr.push("<button onclick=\"gotoApprove('" + i + "');\" type=\"button\" class=\"btn btn-success\">Review</button>");
            $('#datatable-buttons').DataTable().row.add(arr);
        }
        $('#datatable-buttons').DataTable().draw();
    }
}

function getAPendingTerminals()
{
    $.ajax({
        type: "GET",
        url : "/tms/credits/getalldataextra",
        processData: false,
        contentType: false,

        success : function(json) {
            pending = json;
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
    // $("#tmsform").hide();
    // var x = document.getElementById("details").innerText;
    // details = JSON.parse(x);
    // $("#fullname").text(details.fullname);
    getAPendingTerminals();
});