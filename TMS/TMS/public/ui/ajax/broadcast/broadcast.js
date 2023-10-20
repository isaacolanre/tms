var record;
var edit = false;
var gId = 0;
var banks = null;

$("#newclicked").click(function(){
    $("#tmsform").show();
    $("#tmstable").hide();
 });

 $("#backclicked").click(function(){
    $("#tmsform").hide();
    $("#tmstable").show();
    $("#destinationip").val("");
    $("#destinationport").val("");
    $("#url").val("");
    $("#protocol").val("");
    $("#merchantname").val("");
    $("#merchantid").val("");
    $("#remarks").val("");
 });

function gotoEdit(id)
{
    edit = true;
    gId = record[id].id;
    $("#tmsform").show();
    $("#tmstable").hide();
    $("#destinationip").val(record[id].destinationip);
    $("#destinationport").val(record[id].destinationport);
    $("#url").val(record[id].url);
    $("#merchantname").val(record[id].merchantname);
    $("#merchantid").val(record[id].merchantid);
    $("#banks").val(record[id].bankid.toString()).change();
    $("#protocol").val(record[id].protocol.toString()).change();
    $("#remarks").val(record[id].remarks);
}

$("#demo-form2" ).submit(function( event ) {
    event.preventDefault();
    $("#btnsend").hide();
    var fd = new FormData();
    fd.append('destinationip', $("#destinationip").val());
    fd.append('destinationport', $("#destinationport").val());
    fd.append('url', $("#url").val());
    fd.append('protocol', $("#protocol").val());
    fd.append('merchantname', $("#merchantname").val());
    fd.append('merchantid', $("#merchantid").val());
    if($("#banks").val() === "none")
    {
        fd.append('bankid', "");
        fd.append('bankname', "");
        fd.append('bankcode', "");
    }else
    {
        var a = -1;
        var i = banks.length - 1;
        for(; i > -1; i--) {
            if(banks[i].id === $("#banks").val())
            {
                a = i;
                break;
            }
        }
        fd.append('bankid', $("#banks").val());
        fd.append('bankname', banks[a].name);
        fd.append('bankcode', banks[a].code);
    }
    fd.append('remarks', $("#remarks").val());
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
        url : "/tms/broadcast/show",
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
        text: "Are you sure you want to delete " + record[id].destinationip + ":"
            + record[id].destinationport + record[id].url + "?",
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
                url : "/tms/broadcast/deletedata/" + record[id].id,
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
            arr.push(record[i].destinationip);
            arr.push(record[i].destinationport);
            arr.push(record[i].protocol);
            arr.push(record[i].url);
            arr.push("<button onclick=\"gotoEdit('" + i + "');\" type=\"button\" class=\"btn btn-success\">Edit</button>");
            arr.push("<button onclick=\"gotoDelete('" + i + "');\" type=\"button\" class=\"btn btn-success\">Delete</button>");
            $('#datatable-buttons').DataTable().row.add(arr);
        }
        $('#datatable-buttons').DataTable().draw();
    }
}

function getAllData()
{
    $.ajax({
        type: "GET",
        url : "/tms/broadcast/getalldata",
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

function processBanks()
{
    if(banks === null)
    {
        //Do nothing because it is null
    }else
    {
        var i = banks.length - 1;
        for(; i > -1; i--) {
            $("#banks").append('<option value=' + banks[i].id + '>' + banks[i].name + '</option');
        }
    }
}

function getAllBanks()
{
    $.ajax({
        type: "GET",
        url : "/tms/banks/getalldata",
        processData: false,
        contentType: false,

        success : function(json) {
            banks = JSON.parse(json.message);
            processBanks();
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
    getAllBanks();
});