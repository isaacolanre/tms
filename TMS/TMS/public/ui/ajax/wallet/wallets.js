
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
            "url": "/tms/wallet/getallwallet/" + startdate + "/" + enddate,
            "dataSrc": "",
        },
        "columns": [
            { "data": "id" },
            { "data": "walletid" },
            { "data": "username" },
            { "data": "status" },
            { "data": "amount" },
            { "data": "usertype" },
            { "data": "kudaactnum" },
            { "data": "fullname" }
        ]
    });
}

function displayParticularData(data)
{
    console.log(data.username);
    //window.location.href = "/tms/wallet/details/" + data.username;
    window.open("/tms/wallet/details/" + data.username, '_blank');
}

$("#table_refresh a").click(function () {
    calculateDateRange();
});

$(document).ready(function() {
    calculateDateRange();
});
