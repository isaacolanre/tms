var record;
var edit = false;
var gId = 0;
var banks = null;


$( "#btnAppr" ).click(function() {
    //event.preventDefault();
    $("#btnAppr").hide();
    var fd = new FormData();
    fd.append('version', $("#version").val());
    fd.append('description', $("#description").val());
    var a = -1;
    var i = banks.length - 1;
    for(; i > -1; i--) {
        if(banks[i].id === $("#banks").val())
        {
            a = i;
            break;
        }
    }
    fd.append('bankname', banks[a].name);
    fd.append('bankcode', banks[a].code);
    fd.append('isreceipt', $("#logotype").val());
    fd.append('upload', upload.files[0]);
    fd.append('remarks', $("#remark").val());

    swal({
        title: 'Application',
        text: "Are you sure you want to add logo for " + banks[a].name,
        type: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#001e33',
        cancelButtonColor: '#800080',
        confirmButtonText: 'Yes, Add!'
    }).then(function (result) {
        if (result.value)
        {
            swal({
                title: "Processing...",
                text: "Please wait",
                //imageUrl: "images/ajaxloader.gif",
                showConfirmButton: false,
                allowOutsideClick: false
            });
            $.ajax({
                type: "POST",
                url : "/tms/logo/logo",
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
                    $("#btnAppr").show();
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
        }else
        {
            $("#btnsend").show();
        }
    });
});

function gotoDelete(id)
{
    swal({
        title: "Delete?",
        text: "Are you sure you want to delete logo for for " + record[id].bankname + "?",
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
                url : "/tms/logo/deletelogo/" + record[id].id,
                data : fd,
                processData: false,
                contentType: false,
        
                success : function(json) {
                    swal(
                        'Done!',
                        "Logo for " + record[id].bankname + " is deleted.",
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
                        "Logo for " + record[id].bankname + " not deleted.",
                        'error'
                    );
                }
            });
        }else
        {

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
            banks = json;
            processBanks();
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
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
            arr.push(record[i].bankname);
            if(record[i].isreceipt === "true")
                arr.push("YES");
            else
                arr.push("NO");
            arr.push(record[i].version);
            arr.push("<a href=" + record[i].download + "><i class=\"fa fa-download\"></i> Download</a>");
            arr.push("<button onclick=\"gotoDelete('" + i + "');\" type=\"button\" class=\"btn btn-success\">Delete</button>");
            $('#datatable-buttons').DataTable().row.add(arr);
        }
        $('#datatable-buttons').DataTable().draw();
    }
}

function getAllLogo()
{
    $.ajax({
        type: "GET",
        url : "/tms/logo/getalllogos",
        processData: false,
        contentType: false,

        success : function(json) {
            record = json;
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
    getAllLogo();
    getAllBanks();
});


$("#goBack").click(function() {
    $("#tableView").show();
    $("#formView").hide();
    $("#version").val("");
    $("#description").val("");
    $("#remarks").val("");
});

$("#table_pull a").click(function () {
    $("#tableView").hide();
    $("#formView").show();
});