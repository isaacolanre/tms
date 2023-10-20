var record;
var edit = false;
var gId = 0;
var profiles = null;

function gotoEdit(id)
{
    edit = true;
    gId = record[id].id;
    //Start here
    $("#tmsform").show();
    $("#tmstable").hide();
    $("#tid").val(record[id].tid);
    $("#profile").val(record[id].profileid.toString()).change();
    $("#adminpin").val(record[id].adminpin);
    $("#changepin").val(record[id].changepin.toString()).change();
    $("#merchantpin").val(record[id].merchantpin);
    $("#merchantname").val(record[id].merchantname);
    $("#merchantaddress").val(record[id].merchantaddress);
    $("#blocked").val(record[id].blocked.toString()).change();
    $("#blockedpin").val(record[id].blockedpin);
    $("#serialnumber").val(record[id].serialnumber);
    $("#initapplicationversion").val(record[id].initapplicationversion);
    $("#terminalmodel").val(record[id].terminalmodel);
    $("#ownerusername").val(record[id].ownerusername);
}

$("#exportbutton").click(function(e){
    $("#exportbutton").text("Please Wait");
    $("#exportbutton").prop("disabled",true);
    var table = $('#datatable-buttons').DataTable();
    var data = table.rows({filter: 'applied'}).data();
    var exp = [];
    for(var i = 0; i < data.length; i++)
    {
        var tid = data[i][0];
        var index = record.findIndex(obj => obj.tid == tid);
        if(index === -1)
            continue;
        var dat = record[index];
        exp.push(dat);
    }
    var myTestXML = new myExcelXML(JSON.stringify(exp));
    myTestXML.downLoad();
    $("#exportbutton").text("Export");
    $("#exportbutton").prop("disabled",false);
});

$("#demo-form2" ).submit(function( event ) {
    event.preventDefault();
    $("#btnsend").hide();
    var fd = new FormData();
    var a = -1;
    var i = profiles.length - 1;
    
    for(; i > -1; i--) {
        if(profiles[i].id === $("#profile").val())
        {
            a = i;
            fd.append('profilename', profiles[a].name);
            fd.append('profileid', profiles[a].id);
            break;
        }
    }
    
    fd.append('tid', $("#tid").val());
    fd.append('adminpin', $("#adminpin").val());
    fd.append('changepin', $("#changepin").val());
    fd.append('merchantpin', $("#merchantpin").val());
    fd.append('merchantname', $("#merchantname").val());
    fd.append('merchantaddress', $("#merchantaddress").val());
    fd.append('blocked', $("#blocked").val());
    fd.append('blockedpin', $("#blockedpin").val());
    fd.append('serialnumber', $("#serialnumber").val());
    fd.append('initapplicationversion', $("#initapplicationversion").val());
    fd.append('terminalmodel', $("#terminalmodel").val());
    fd.append('ownerusername', $("#ownerusername").val());

    $.ajax({
        type: "POST",
        url : "/tms/terminals/show",
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

$("#demo-form3" ).submit(function( event ) {
    event.preventDefault();
    
    var fd = new FormData();
    fd.append('upload', upload.files[0]);
    $("#btnsend2").hide();
    $.ajax({
        type: "POST",
        url : "/tms/terminals/batch",
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
            $("#btnsend2").show();
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
        text: "Are you sure you want to delete " + record[id].tid + "?",
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
            $.ajax({
                type: "DELETE",
                url : "/tms/terminals/deleteterminals/" + record[id].id,
                data : fd,
                processData: false,
                contentType: false,
        
                success : function(json) {
                    swal(
                        'Done!',
                        record[id].tid + " is deleted.",
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
                        record[id].tid + " not deleted.",
                        'error'
                    );
                }
            });
        }else
        {

        }
    });
}

function parseProfile()
{
    if(profiles === null)
    {
        //Do nothing because it is null
    }else
    {
        var i = profiles.length - 1;
        for(; i > -1; i--) {
            $("#profile").append('<option value=' + profiles[i].id + '>' + profiles[i].name + '</option');
        }
    }
}

function getAllProfile()
{
    $.ajax({
        type: "GET",
        url : "/tms/profile/getalldata",
        processData: false,
        contentType: false,

        success : function(json) {
            profiles = JSON.parse(json.message);
            parseProfile();
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
            arr.push(record[i].tid);
            arr.push(record[i].profilename);
            arr.push(record[i].blocked);
            arr.push("<button onclick=\"gotoEdit('" + i + "');\" type=\"button\" class=\"btn btn-success\">Edit</button>");
            arr.push("<button onclick=\"gotoDelete('" + i + "');\" type=\"button\" class=\"btn btn-success\">Delete</button>");
            $('#datatable-buttons').DataTable().row.add(arr);
        }
        $('#datatable-buttons').DataTable().draw();
    }
}

function getAllTerminals()
{
    $.ajax({
        type: "GET",
        url : "/tms/terminals/getalldata",
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
    getAllProfile();
    getAllTerminals();
});