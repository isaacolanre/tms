var startdate = "";
var enddate = "";

function getMonth(mnth)
{
  if(mnth.indexOf("Jan") !== -1)
  {
    return "01";
  }else if(mnth.indexOf("Feb") !== -1)
  {
    return "02";
  }else if(mnth.indexOf("Mar") !== -1)
  {
    return "03";
  }else if(mnth.indexOf("Apr") !== -1)
  {
    return "04";
  }else if(mnth.indexOf("May") !== -1)
  {
    return "05";
  }else if(mnth.indexOf("Jun") !== -1)
  {
    return "06";
  }else if(mnth.indexOf("Jul") !== -1)
  {
    return "07";
  }else if(mnth.indexOf("Aug") !== -1)
  {
    return "08";
  }else if(mnth.indexOf("Sep") !== -1)
  {
    return "09";
  }else if(mnth.indexOf("Oct") !== -1)
  {
    return "10";
  }else if(mnth.indexOf("Nov") !== -1)
  {
    return "11";
  }else if(mnth.indexOf("Dec") !== -1)
  {
    return "12";
  }else
  {
    return "01";
  }
}

function getDay(day)
{
    if(parseInt(day) < 10)
        return "0" + parseInt(day);
    return day;
}

function calculateDateRange()
{
    var table = $('#datatable-buttons').DataTable({
        "language": {
            "emptyTable": "No Records"
        },
        "bDestroy": true
    });

    table.destroy();

    var table = $('#datatable-buttons').DataTable( {
        "scrollX": true,
        "fnRowCallback": function (nRow, aData, iDisplayIndex) {
            // Bind click event
            $(nRow).click(function() {
                displayParticularData(aData);
            });
            return nRow;
        },
        dom: 'Bfrltip',
        buttons: [
            'copy', 'csv', 'excel', 'pdf', 'print'
        ],
        "ajax": {
            "url": "/tms/settings/getallcomms",
            "dataSrc": "",
        },
        "columns": [
            { "data": "id" },
            { "data": "name" },
            { "data": "commstype" },
            { "data": "apn" },
            { "data": "port" }
        ]
    });
}

function calculateAll()
{
    $("#tableView").hide();
    $("#formView").show();
    $("#name").val("");
    $("#username").val("");
    $("#gateway").val("");
    $("#ip").val("");
    $("#port").val("");
    $("#apn").val("");
    $("#password").val("");
    $("#remark").val("");
    id = 0;
}

var id = 0;
var fldata;

$( "#btnAppr" ).click(function() {

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
    if(id)
    {
        fd.append('edit', true);
        fd.append('id', id);
    }else
    {
        fd.append('edit', false);
        fd.append('id', id);
    }
    $.ajax({
        type: "POST",
        url : "/tms/settings/communications/",
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

$( "#btnDcl" ).click(function() {
    swal({
        title: "Delete?",
        text: "Are you sure you want to delete " + fldata.name + "?",
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
            fd.append('username', fldata.id);
            $.ajax({
                type: "DELETE",
                url : "/tms/settings/deletecomm/" + fldata.id,
                data : fd,
                processData: false,
                contentType: false,
        
                success : function(json) {
                    swal(
                        'Done!',
                        fldata.name + " deleted.",
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
                        fldata.name + " not deleted.",
                        'error'
                    );
                }
            });
        }else
        {

        }
    });
});

$("#goBack").click(function() {
  $("#tableView").show();
  $("#formView").hide();
});

function displayParticularData(data)
{
    $("#tableView").hide();
    $("#formView").show();

    id = data.id;
    fldata = data;

    $("#name").val(data.name);
    $("#username").val(data.username);
    $("#gateway").val(data.gateway);
    $("#ip").val(data.ip);
    $("#port").val(data.port);
    $("#apn").val(data.apn);
    $("#password").val(data.password);
    $("#remark").val(data.remarks);
    $("#commstype").val(data.commstype.toString()).change();
    $("#ipmode").val(data.ipmode.toString()).change();
}

$("#table_pull a").click(function () {
  calculateAll();
});

$(document).ready(function() {
    calculateDateRange();
});