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
    $("#name").val("");
    $("#username").val("");
    $("#gateway").val("");
    $("#ip").val("");
    $("#port").val("");
    $("#apn").val("");
    $("#password").val("");
    $("#remark").val("");
 });

function gotoEdit(id)
{
    edit = true;
    gId = record[id].id;
    $("#tmsform").show();
    $("#tmstable").hide();
    $("#name").val(record[id].name);
    $("#username").val(record[id].username);
    $("#gateway").val(record[id].gateway);
    $("#ip").val(record[id].ip);
    $("#port").val(record[id].port);
    $("#apn").val(record[id].apn);
    $("#password").val(record[id].password);
    $("#remark").val(record[id].remark);
    $("#commstype").val(record[id].commstype.toString()).change();
    $("#ipmode").val(record[id].ipmode.toString()).change();
}

$("#demo-form2" ).submit(function( event ) {
    event.preventDefault();
    $("#btnsend").hide();
    var fd = new FormData();
    fd.append('name', $("#name").val());
    fd.append('username', $("#username").val());
    fd.append('gateway', $("#gateway").val());
    fd.append('ip', $("#ip").val());
    fd.append('port', $("#port").val());
    fd.append('apn', $("#apn").val());
    fd.append('password', $("#password").val());
    fd.append('commstype', $("#commstype").val());
    fd.append('ipmode', $("#ipmode").val());
    fd.append('remark', $("#remark").val());
    fd.append('edit', edit);
    fd.append('id', gId);

    swal({
        title: "Processing...",
        text: "Please wait",
        //imageUrl: "images/ajaxloader.gif",
        showConfirmButton: false,
        allowOutsideClick: false
    });

    $.ajax({
        type: "POST",
        url : "/tms/settings/communications",
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

function gotoDelete(id)
{
    swal({
        title: "Delete?",
        text: "Are you sure you want to delete " + record[id].name + "?",
        type: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#800080',
        cancelButtonColor: '#001e33',
        confirmButtonText: 'Yes, Delete!'
    }).then(function (result) {
        if (result.value) {
            swal({
                title: "Processing...",
                text: "Please wait",
                //imageUrl: "images/ajaxloader.gif",
                showConfirmButton: false,
                allowOutsideClick: false
            });
            var fd = new FormData();
            fd.append('username', record[id].username);
            $.ajax({
                type: "DELETE",
                url : "/tms/settings/deletecomm/" + record[id].id,
                data : fd,
                processData: false,
                contentType: false,
        
                success : function(json) {
                    swal(
                        'Done!',
                        record[id].name + " deleted.",
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
                        record[id].name + " not deleted.",
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
            arr.push(record[i].name);
            arr.push(record[i].commstype);
            arr.push(record[i].apn);
            arr.push(record[i].port);
            arr.push("<button onclick=\"gotoEdit('" + i + "');\" type=\"button\" class=\"btn btn-success\">Edit</button>");
            arr.push("<button onclick=\"gotoDelete('" + i + "');\" type=\"button\" class=\"btn btn-success\">Delete</button>");
            $('#datatable-buttons').DataTable().row.add(arr);
        }
        $('#datatable-buttons').DataTable().draw();
    }
}

function getAllCommunication()
{
    $.ajax({
        type: "GET",
        url : "/tms/settings/getallcomms",
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
    getAllCommunication();
});