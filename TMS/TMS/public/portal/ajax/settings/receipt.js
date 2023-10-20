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
    $("#footertext").val("");
    $("#customercopylabel").val("");
    $("#merchantcopylabel").val("");
    $("#footnotelabel").val("");
    $("#normalfontsize").val("");
    $("#headerfontsize").val("");
    $("#amountfontsize").val("");
    $("#printmerchantcopynumber").val("");
    $("#printclientcopynumber").val("");
 });

function gotoEdit(id)
{
    edit = true;
    gId = record[id].id;
    $("#tmsform").show();
    $("#tmstable").hide();
    $("#name").val(record[id].name);
    $("#footertext").val(record[id].footertext);
    $("#customercopylabel").val(record[id].customercopylabel);
    $("#merchantcopylabel").val(record[id].merchantcopylabel);
    $("#footnotelabel").val(record[id].footnotelabel);
    $("#normalfontsize").val(record[id].normalfontsize);
    $("#headerfontsize").val(record[id].headerfontsize);
    $("#amountfontsize").val(record[id].amountfontsize);
    $("#printmerchantcopynumber").val(record[id].printmerchantcopynumber);
    $("#printclientcopynumber").val(record[id].printclientcopynumber);
    $("#showlogo").val(record[id].showlogo.toString()).change();
    $("#showbarcode").val(record[id].showbarcode.toString()).change();
    $("#saveforreceipt").val(record[id].saveforreceipt.toString()).change();
}

$("#demo-form2" ).submit(function( event ) {
    event.preventDefault();
    $("#btnsend").hide();
    var fd = new FormData();
    fd.append('name', $("#name").val());
    fd.append('footertext', $("#footertext").val());
    fd.append('customercopylabel', $("#customercopylabel").val());
    fd.append('merchantcopylabel', $("#merchantcopylabel").val());
    fd.append('footnotelabel', $("#footnotelabel").val());
    fd.append('normalfontsize', $("#normalfontsize").val());
    fd.append('headerfontsize', $("#headerfontsize").val());
    fd.append('amountfontsize', $("#amountfontsize").val());
    fd.append('printmerchantcopynumber', $("#printmerchantcopynumber").val());
    fd.append('printclientcopynumber', $("#printclientcopynumber").val());
    fd.append('showlogo', $("#showlogo").val());
    fd.append('showbarcode', $("#showbarcode").val());
    fd.append('saveforreceipt', $("#saveforreceipt").val());
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
        url : "/tms/settings/receipts",
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
                url : "/tms/settings/deletereceipt/" + record[id].id,
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
            arr.push(record[i].footertext);
            arr.push(record[i].showlogo);
            arr.push(record[i].showbarcode);
            arr.push("<button onclick=\"gotoEdit('" + i + "');\" type=\"button\" class=\"btn btn-success\">Edit</button>");
            arr.push("<button onclick=\"gotoDelete('" + i + "');\" type=\"button\" class=\"btn btn-success\">Delete</button>");
            $('#datatable-buttons').DataTable().row.add(arr);
        }
        $('#datatable-buttons').DataTable().draw();
    }
}

function getAllReceipt()
{
    $.ajax({
        type: "GET",
        url : "/tms/settings/getallreceipts",
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
    getAllReceipt();
});