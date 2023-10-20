
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
            "url": "/tms/signup/getsignup/" + startdate + "/" + enddate,
            "dataSrc": "",
        },
        "columns": [
            { "data": "id" },
            { "data": "username" },
            { "data": "fullname" },
            { "data": "dob" },
            { "data": "gender" },
            { "data": "bvn" },
            { "data": "phonenumber" },
            { "data": "bankname" },
            { "data": "accountnumber" },
            { "data": "approved" },
            { "data": "businessname" },
            { "data": "state" },
            { "data": "serialnumber" },
            { "data": "walletid" },
            { "data": "kudaactnum" },
            { "data": "usertype" }
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
            "url": "/tms/signup/getallsignup",
            "dataSrc": "",
        },
        "columns": [
            { "data": "id" },
            { "data": "username" },
            { "data": "fullname" },
            { "data": "dob" },
            { "data": "gender" },
            { "data": "bvn" },
            { "data": "phonenumber" },
            { "data": "bankname" },
            { "data": "accountnumber" },
            { "data": "approved" },
            { "data": "businessname" },
            { "data": "state" },
            { "data": "serialnumber" },
            { "data": "walletid" },
            { "data": "kudaactnum" },
            { "data": "usertype" }
        ]
    });

}

var id = 0;
var fldata;

$( "#btnAppr" ).click(function() {

  if(fldata.imageurla && fldata.imageurlb)
  {
    var fd = new FormData();
    fd.append('aggregator', $("#aggregator").val());
    fd.append('staff', $("#staff").val());
    fd.append('username', $("#username").val());
    fd.append('usertype', $("#usertype").val());
    $.ajax({
      type: "POST",
      url : "/tms/signup/approve/" + id,
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
  }else
  {
    swal(
        'Missing Pictures!',
        'Both Images Must be Uploaded',
        'error'
    );
  }
});

$( "#btnDcl" ).click(function() {
    $.ajax({
      type: "GET",
      url : "/tms/signup/decline/" + id,
      //data : fd,
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

$( "#rejIma" ).click(function() {
  $.ajax({
      type: "GET",
      //"/tms/signup/getsignup/" + startdate + "/" + enddate
      url : "/tms/signup/deletea/" + id,
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

$("#rejImb").click(function() {
  $.ajax({
      type: "GET",
      url : "/tms/signup/rejectb/" + id,
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

$("#goBack").click(function() {
  $("#tableView").show();
  $("#formView").hide();
});

function displayParticularData(data)
{
    //console.log(data);
    //console.log(data.approved);
    //console.log(data.fullname);
    $("#tableView").hide();
    $("#formView").show();

    id = data.id;
    fldata = data;

    if(data.approved && data.approved === "true")
    {
        //console.log("here 1");
      $("#status").val("true");
      $("#approvedby").val(data.approvedby);
      $("#btnAppr").hide();
      $("#btnDcl").show();
    }else
    {
        //console.log("here 2");
      $("#status").val("false");
      $("#approvedby").val(data.approvedby);
      $("#btnDcl").hide();
      $("#btnAppr").show();
    }

    data.gender === "M" ? $("#gender").val("Male") : $("#gender").val("Female");
    $("#phone").val(data.phonenumber);
    $("#bvn").val(data.bvn);

    $("#imagea").attr("src", "http://192.46.223.163:8088/" + data.imageurla);
    $("#imageb").attr("src", "http://192.46.223.163:8088/" + data.imageurlb);

    $("#username").val(data.username);
    $("#fullnamex").val(data.fullname);
    $("#housenumber").val(data.housenumber);
    $("#streetname").val(data.streetname);
    $("#dob").val(data.dob);
    $("#nin").val(data.nin);
    $("#bankname").val(data.bankname);
    $("#accountnumber").val(data.accountnumber);
    $("#bankcode").val(data.bankcode);
    $("#accountholder").val(data.accountholder);
    $("#businessname").val(data.businessname);
    $("#businessaddress").val(data.businessaddress);
    $("#businesstype").val(data.businesstype);
    $("#businessphone").val(data.businessphone);
    $("#state").val(data.state);
    $("#lga").val(data.lga);
    $("#city").val(data.city);
    $("#cac").val(data.cacnumber);
    $("#serialnumber").val(data.serialnumber);
    $("#walletid").val(data.walletid);
    $("#kudaaccount").val(data.kudaactnum);
    $("#kudatrack").val(data.kudatrack);
    $("#usertype").val(data.usertype);
    $("#landmark").val(data.landmark);
    //$("#aggregator").val(data.aggregator);
    //$("#staff").val(data.staff);
    $("#aggregator").val(data.aggregator.toString()).change();
    $("#staff").val(data.staff.toString()).change();

    //data.ssl.toString()).change();
}

$("#table_refresh a").click(function () {
    calculateDateRange();
});

$("#table_pull a").click(function () {
  calculateAll();
});

function getUsersAggregator()
{
    $.ajax({
        type: "GET",
        url : "/tms/signup/getallusers/",
        //data : fd,
        processData: false,
        contentType: false,

        success : function(json) {
            console.log(json);
            for(var i = 0; i < json.length; i++) {
                if(json[i].role === "user")
                    $("#ustaff").append("<option value=\"" + json[i].username + "\">" + json[i].fullname + "</option>");
                else
                    $("#uaggregator").append("<option value=\"" + json[i].username + "\">" + json[i].fullname + "</option>");
            }
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
        }
    });
}

$(document).ready(function() {
    getUsersAggregator();
    calculateDateRange();
});

