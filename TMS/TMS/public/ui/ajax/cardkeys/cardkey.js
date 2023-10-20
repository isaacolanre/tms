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
    $("#keyindex").val("");
    $("#modulus").val("");
    $("#exponent").val("");
    $("#expirydate").val("");
    $("#aid").val("");
    $("#length").val("");
    $("#checksum").val("");
    $("#remarks").val("");
 });

function gotoEdit(id)
{
    edit = true;
    gId = record[id].id;
    $("#tmsform").show();
    $("#tmstable").hide();
    $("#name").val(record[id].name);
    $("#keyindex").val(record[id].keyindex);
    $("#modulus").val(record[id].modulus);
    $("#exponent").val(record[id].exponent);
    $("#expirydate").val(record[id].expirydate);
    $("#aid").val(record[id].aid);
    $("#length").val(record[id].length);
    $("#keytype").val(record[id].keytype.toString()).change();
    $("#partialmatch").val(record[id].partialmatch.toString()).change();
    $("#checksum").val(record[id].checksum);
    $("#remarks").val(record[id].remarks);
}

$("#demo-form2" ).submit(function( event ) {
    event.preventDefault();
    $("#btnsend").hide();
    var fd = new FormData();
    fd.append('name', $("#name").val());
    fd.append('keyindex', $("#keyindex").val());
    fd.append('modulus', $("#modulus").val());
    fd.append('exponent', $("#exponent").val());
    fd.append('expirydate', $("#expirydate").val());
    fd.append('aid', $("#aid").val());
    fd.append('keylength', $("#length").val());
    fd.append('keytype', $("#keytype").val());
    fd.append('partialmatch', $("#partialmatch").val());
    fd.append('checksum', $("#checksum").val());
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
        url : "/tms/cardkeys/show",
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
                url : "/tms/cardkeys/deletedata/" + record[id].id,
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
            arr.push(record[i].expirydate);
            arr.push(record[i].exponent);
            arr.push(record[i].aid);
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
        url : "/tms/cardkeys/getalldata",
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