var record;
var edit = false;
var gId = 0;

$("#newclicked").click(function(){
    $("#tmsform").show();
    $("#tmstable").hide();
});

$("#backclicked").click(function(){
    $("#tmsform").hide();
    $("#tmstable").show();
    $("#email").val("");
    $("#amount").val("");
});


$("#byuser").click(function(){
    swal({
        title: 'Wallet Credits',
        text: "User Email Address",
		input: 'text',
        type: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#800080',
        cancelButtonColor: '#001e33',
        confirmButtonText: 'Pull'
    }).then(function (result) {
		if (result.value) 
		{
			if(1)
            {
                var table = $('#datatable-buttons').DataTable({
                        "language": {
                            "emptyTable": "Please Wait. Loading..."
                        },
                        "bDestroy": true
                });
                table.clear().draw();
                console.log(result.value);
                $.ajax({
                    url: "/tms/credits/getbyemail/" + result.value + "/",
                    async: true,
                    dataType: 'json',
                    success: function (data) {
                        console.log(data.message);
                        record = JSON.parse(data.message);
                        //console.log(records);
                        //record = JSON.parse(json.message);
                        parseResponse();
                    },
                    error : function(xhr,errmsg,err) {
                        var table = $('#datatable-buttons').DataTable({
                                "language": {
                                    "emptyTable": "Please Reload Page."
                                },
                                "bDestroy": true
                        });
                        table.clear().draw();
                    }
                });
            }
		}
    });
});


$("#demo-form2" ).submit(function( event ) {
    event.preventDefault();
    $("#btnsend").hide();
    var fd = new FormData();
    fd.append('email', $("#email").val());
    fd.append('amount', $("#amount").val());
    
    swal({
        title: "Processing...",
        text: "Please wait",
        //imageUrl: "images/ajaxloader.gif",
        showConfirmButton: false,
        allowOutsideClick: false
    });

    $.ajax({
        type: "POST",
        url : "/tms/credits/show",
        data : fd,
        processData: false,
        contentType: false,

        success : function(json) {
            swal({
                title: "Successful!",
                showConfirmButton: false,
                timer: 1000
            });
            if(json.status == 200)
            {
                location.reload();
            }
        },

        complete: function(){
            $("#btnsend").show();
        },
        
        error : function(xhr,errmsg,err) {
            swal({
                title: "Error!",
                showConfirmButton: false,
                timer: 1000
            });
            var json = JSON.parse(xhr.responseText);
            swal(
                'Error!',
                json.message,
                'error'
            );
        }
    });
});

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
            arr.push(record[i].email);
            arr.push(record[i].amount);
            arr.push(record[i].initiator);
            arr.push(record[i].timeinitiated);
            arr.push(record[i].approvedby);
            arr.push(record[i].timeapproved);
            $('#datatable-buttons').DataTable().row.add(arr);
        }
        $('#datatable-buttons').DataTable().draw();
    }
}

function getAllData()
{
    $.ajax({
        type: "GET",
        url : "/tms/credits/getalldata",
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