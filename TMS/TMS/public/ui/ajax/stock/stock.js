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
    var str = $("#Select_date").text();
    if(str.indexOf("-") !== -1)
    {
        var chr = str.indexOf(" - ");
        var year = new Date().getFullYear();
        var realDate = $("#Select_date").text();
        var month = getMonth(realDate.slice(0, 3));
        var day = getDay(realDate.slice(4, chr));
        startdate = year + "-" + month + "-" + day;
        month = getMonth(realDate.slice(chr + 3, chr + 3 + 3));
        day = getDay(realDate.slice(chr + 3 + 4));
        enddate = year + "-" + month + "-" + day;
    }else
    {
        var year = new Date().getFullYear();
        var realDate = $("#Select_date").text();
        var month = getMonth(realDate.slice(0, 3));
        var day = getDay(realDate.slice(4));
        startdate = year + "-" + month + "-" + day;
        enddate = startdate;
    }
    
    
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
            "url": "/tms/stock/getstock/" + startdate + "/" + enddate,
            "dataSrc": "",
        },
        "columns": [
            { "data": "id" },
            { "data": "serialnumber" },
            { "data": "model" },
            { "data": "terminalid" },
            { "data": "appversion" }
        ]
    });

}

function calculateAll()
{
    var str = $("#Select_date").text();
    if(str.indexOf("-") !== -1)
    {
        var chr = str.indexOf(" - ");
        var year = new Date().getFullYear();
        var realDate = $("#Select_date").text();
        var month = getMonth(realDate.slice(0, 3));
        var day = getDay(realDate.slice(4, chr));
        startdate = year + "-" + month + "-" + day;
        month = getMonth(realDate.slice(chr + 3, chr + 3 + 3));
        day = getDay(realDate.slice(chr + 3 + 4));
        enddate = year + "-" + month + "-" + day;
    }else
    {
        var year = new Date().getFullYear();
        var realDate = $("#Select_date").text();
        var month = getMonth(realDate.slice(0, 3));
        var day = getDay(realDate.slice(4));
        startdate = year + "-" + month + "-" + day;
        enddate = startdate;
    }
    
    // console.log(startdate);
    // console.log(enddate);
    
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
            "url": "/tms/stock/getallstock",
            "dataSrc": "",
        },
        "columns": [
            { "data": "id" },
            { "data": "serialnumber" },
            { "data": "model" },
            { "data": "terminalid" },
            { "data": "appversion" }
        ]
    });

}

$("#btnApprUp").click(function() {
    $("#btnApprUp").hide();
    var fd = new FormData();
    fd.append('upload', upload.files[0]);
    $.ajax({
        type: "POST",
        url : "/tms/stock/batch",
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
            $("#btnApprUp").show();
        },
        
        error : function(xhr,errmsg,err) {
            $("#btnApprUp").show();
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

var id = 0;
var fldata;

$( "#btnAppr" ).click(function() {
    var fd = new FormData();
    fd.append('terminalname', $("#terminalname").val());
    fd.append('typeofterminal', $("#typeofterminal").val());//typeofterminal
    fd.append('manufacturer', $("#manufacturer").val());
    fd.append('model', $("#model").val());
    fd.append('specs', $("#specs").val());
    fd.append('manufactureddate', $("#manufactureddate").val());
    fd.append('serialnumber', $("#serialnumber").val());
    fd.append('terminalid', $("#terminalid").val());
    fd.append('appversion', $("#appversion").val());
    fd.append('remarks', $("#remarks").val());
    fd.append('edit', true);
    fd.append('id', id);

    $.ajax({
      type: "POST",
      url : "/tms/stock/show",
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
        text: "Are you sure you want to delete " + fldata.serialnumber + "?",
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
                url : "/tms/stock/deletedata/" + fldata.id,
                data : fd,
                processData: false,
                contentType: false,
        
                success : function(json) {
                    swal(
                        'Done!',
                        fldata.serialnumber + " deleted.",
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
                        fldata.serialnumber + " not deleted.",
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

    $("#terminalname").val(data.terminalname);
    $("#typeofterminal").val(data.typeofterminal.toString().toLowerCase()).change();
    $("#manufacturer").val(data.manufacturer);
    $("#model").val(data.model);
    $("#specs").val(data.specs);
    $("#manufactureddate").val(data.manufactureddate);
    $("#serialnumber").val(data.serialnumber);
    $("#terminalid").val(data.terminalid);
    $("#appversion").val(data.appversion);
    $("#remarks").val(data.remarks);
}

$("#table_refresh a").click(function () {
    calculateDateRange();
});

$("#table_pull a").click(function () {
  calculateAll();
});

$(document).ready(function() {
    calculateDateRange();
});

