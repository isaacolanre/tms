





function getLatestFailed()
{
    $.ajax({
        type: "GET",
        url : "/tms/dashboard/lastfailed/recent",
        processData: false,
        contentType: false,

        success : function(json) {
            //console.log(json);
            var ftxn = json;
            var i = ftxn.length - 1;
            $('#dere').empty();
            for(var i = 0; i < ftxn.length; i++) {                   
                $('#failedTab').append('<tr>' +
                    '<td>' + ftxn[i].username + '</td>' + 
                    '<td>' + ftxn[i].tid + '</td>' +
                    '<td>' + ftxn[i].amount + '</td>' +
                    '<td>' + ftxn[i].transname + '</td>' +
                    '<td>' + ftxn[i].status + '</td>'
                    + '</tr>');
            }
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
        }
    });
}

function getLatestSignup()
{
    $.ajax({
        type: "GET",
        url : "/tms/dashboard/signup/recent",
        processData: false,
        contentType: false,

        success : function(json) {
            var signups = json;
            var i = signups.length - 1;
            $('#sDets').empty();
            for(var i = 0; i < signups.length; i++) {                   
                $('#signupTab').append('<tr>' +
                    '<td>' + signups[i].username + '</td>' + 
                    '<td>' + signups[i].state + '</td>' +
                    '<td>' + signups[i].usertype + '</td>' +
                    '<td>' + signups[i].serialnumber + '</td>'
                    + '</tr>');
            }
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
        }
    });
}

var txns;
var sgnCnt = 1;
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
    
    //console.log(startdate);
    //console.log(enddate);

    $.ajax({
        type: "GET",
        url : "/tms/transaction/getalltransaction/" + startdate + "/" + enddate,
        processData: false,
        contentType: false,

        success : function(json) {
            txns = json;
            var i = txns.length - 1;
            var cardAppr = 0.00;
            var cardApprRate = 0;
            var genApprRate = 0;
            var cdrr = 0;
            var array = [];

            var coAppr = 0.00;
            var tnsAppr = 0.00;
            var bpAppr = 0.00;
            var coApprCount = 0;
            var tnsApprCount = 0;
            var bpApprCount = 0;

            var cashout = "";
            var transfers = "";
            var bills = "";
            var cgraph = [];
            var ccc = 0;
            var tgraph = [];
            var ttt = 0;
            for(var i = 0; i < txns.length; i++) {


                if(txns[i].transname === "CASH OUT" || txns[i].transname === "PURCHASE")
                {
                    cashout = cashout + "<div class=\"activity\">" +
                                "<div class=\"activity-info\">" +
                                    "<div class=\"icon-info-activity\">" +
                                        "<i class=\"las la-user-clock bg-soft-primary\"></i>" +
                                    "</div>" +
                                    "<div class=\"activity-info-text\">" +
                                        "<div class=\"d-flex justify-content-between align-items-center\">" +
                                            "<p class=\"text-muted mb-0 font-13 w-75\"><span>" + txns[i].username + "</span>" + 
                                                " performed a cashout of ₦ " + 
                                                parseFloat(txns[i].amount).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,') + " on " + txns[i].timestamp + " <a href=\"#\">PAN: " + txns[i].pan + "</a>" +
                                            "</p>" +
                                            "<small class=\"text-muted\">RESP: " + txns[i].status + "</small>" +
                                        "</div>" +  
                                    "</div>" +
                                "</div>" +                                                                                                                                
                            "</div>";
                }else if(txns[i].transname === "TRANSFER")
                {
                    transfers = transfers + "<div class=\"activity\">" +
                                "<div class=\"activity-info\">" +
                                    "<div class=\"icon-info-activity\">" +
                                        "<i class=\"las la-user-clock bg-soft-primary\"></i>" +
                                    "</div>" +
                                    "<div class=\"activity-info-text\">" +
                                        "<div class=\"d-flex justify-content-between align-items-center\">" +
                                            "<p class=\"text-muted mb-0 font-13 w-75\"><span>" + txns[i].username + "</span>" + 
                                                " performed a transfer of ₦ " + 
                                                parseFloat(txns[i].amount).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,') + " on " + txns[i].timestamp + " <a href=\"#\">BEN: " + txns[i].destination + "</a>" +
                                            "</p>" +
                                            "<small class=\"text-muted\">RESP: " + txns[i].status + "</small>" +
                                        "</div>" +  
                                    "</div>" +
                                "</div>" +                                                                                                                                
                            "</div>";
                }else
                {
                    bills = bills + "<div class=\"activity\">" +
                                "<div class=\"activity-info\">" +
                                    "<div class=\"icon-info-activity\">" +
                                        "<i class=\"las la-user-clock bg-soft-primary\"></i>" +
                                    "</div>" +
                                    "<div class=\"activity-info-text\">" +
                                        "<div class=\"d-flex justify-content-between align-items-center\">" +
                                            "<p class=\"text-muted mb-0 font-13 w-75\"><span>" + txns[i].username + "</span>" + 
                                                " performed a " + txns[i].transname + " of ₦ " + 
                                                parseFloat(txns[i].amount).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,') + " on " + txns[i].timestamp + " <a href=\"#\">BEN: " + txns[i].destination + "</a>" +
                                            "</p>" +
                                            "<small class=\"text-muted\">RESP: " + txns[i].status + "</small>" +
                                        "</div>" +  
                                    "</div>" +
                                "</div>" +                                                                                                                                
                            "</div>";
                }
                if(txns[i].status === "00")
                {
                    if(txns[i].transname === "CASH OUT" || txns[i].transname === "PURCHASE")
                    {
                        coAppr = parseFloat(coAppr) + parseFloat(txns[i].amount);
                        coApprCount = coApprCount + 1;
                        if(parseFloat(txns[i].amount) > 1000)
                        {
                            if(ccc < 12)
                            {
                                cgraph.push(parseFloat(txns[i].amount / 1000).toFixed(2));
                                ccc = ccc + 1;
                            }
                        }
                    }else if(txns[i].transname === "TRANSFER")
                    {
                        tnsAppr = parseFloat(tnsAppr) + parseFloat(txns[i].amount);
                        tnsApprCount = tnsApprCount + 1;
                        if(parseFloat(txns[i].amount) > 1000)
                        {
                            if(ttt < 12)
                            {
                                tgraph.push(parseFloat(txns[i].amount / 1000).toFixed(2));
                                ttt = ttt + 1;
                            }
                        }
                    }else
                    {
                        bpApprCount = bpApprCount + 1;
                        bpAppr = parseFloat(bpAppr) + parseFloat(txns[i].amount);
                    }
                }

                if(array.indexOf(txns[i].username) === -1 )
                    array.push(txns[i].username);
                if(txns[i].transname === "CASH OUT" || txns[i].transname === "PURCHASE")
                {
                    cdrr = cdrr + 1;
                    if(txns[i].status === "00")
                    {
                        cardAppr = parseFloat(cardAppr) + parseFloat(txns[i].amount);
                        cardApprRate = cardApprRate + 1;
                    }
                }
                
                if(txns[i].status !== "00")
                {
                    genApprRate = genApprRate + 1;
                }
            }
            var fcardAppr = parseFloat(cardAppr).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
            $("#apprAmt").text('₦ ' + fcardAppr);
            $("#cardAppRate").text(cardApprRate + '/' + cdrr);
            var cardPer = parseFloat((cardApprRate / cdrr) * 100).toFixed(2);
            $("#cardApprPer").text(cardPer + "%");
            $("#genFilRate").text(genApprRate + '/' + txns.length);
            var genPer = parseFloat((genApprRate / txns.length) * 100).toFixed(2);
            $("#genApprPer").text(genPer + "%");
            $("#txnAgents").text(array.length);
            var txnUsers = parseFloat((array.length / sgnCnt) * 100).toFixed(2);
            $("#txnAgentsPer").text(txnUsers + "%");

            var vcoAppr = parseFloat(coAppr).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
            var vtnsAppr = parseFloat(tnsAppr).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
            var vbpAppr = parseFloat(bpAppr).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
            $("#dtDis").empty();                     
            $('#myTable').append('<tr><td>' + '₦ ' + vcoAppr + '</td>' + 
                '<td>' + '₦ ' + vtnsAppr + '</td>' +
                '<td>' + '₦ ' + vbpAppr + '</td>'
                + '</tr>');
            $('#myTable').append('<tr><td>' + 'Count: ' + coApprCount + '</td>' + 
                '<td>' + 'Count: ' + tnsApprCount + '</td>' +
                '<td>' + 'Count: ' + bpApprCount + '</td>'
                + '</tr>');
            
            $("#cashoutDiv").empty();
            $("#cashoutDiv").append("<div  class=\"analytic-dash-activity\" data-simplebar>" + cashout + "</div>");
            $("#transfersDiv").empty();
            $("#transfersDiv").append("<div  class=\"analytic-dash-activity\" data-simplebar>" + transfers + "</div>");
            $("#billsDiv").empty();
            $("#billsDiv").append("<div  class=\"analytic-dash-activity\" data-simplebar>" + bills + "</div>");
        
            var ctbTot = parseFloat(coAppr + tnsAppr + bpAppr).toFixed(2);
            $("#tAmt").text('Transaction Amount for ' + $("#Select_date").text() 
            + ' is ₦ ' + parseFloat(ctbTot).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,'));
            var ctbcoAppr = parseFloat((coAppr / ctbTot) * 100).toFixed(2);
            var ctbtnsAppr = parseFloat((tnsAppr/ ctbTot) * 100).toFixed(2);
            var ctbbpAppr = parseFloat((bpAppr/ ctbTot) * 100).toFixed(2);
            
            var darr = [];
            

            darr.push(parseFloat(ctbcoAppr));
            darr.push(parseFloat(ctbtnsAppr));
            darr.push(parseFloat(ctbbpAppr));
            
            var options = {
                chart: {
                    height: 270,
                    type: 'donut',
                }, 
                plotOptions: {
                  pie: {
                    donut: {
                      size: '85%'
                    }
                  }
                },
                dataLabels: {
                  enabled: false,
                },
              
                stroke: {
                  show: true,
                  width: 2,
                  colors: ['transparent']
                },
               
                series: darr,
                legend: {
                  show: true,
                  position: 'bottom',
                  horizontalAlign: 'center',
                  verticalAlign: 'middle',
                  floating: false,
                  fontSize: '13px',
                  offsetX: 0,
                  offsetY: 0,
                },
                labels: [ "Card","Transfers", "Bills" ],
                colors: ["#2a76f4","rgba(42, 118, 244, .5)","rgba(42, 118, 244, .18)"],
               
                responsive: [{
                    breakpoint: 600,
                    options: {
                      plotOptions: {
                          donut: {
                            customScale: 0.2
                          }
                        },        
                        chart: {
                            height: 240
                        },
                        legend: {
                            show: false
                        },
                    }
                }],
                tooltip: {
                  y: {
                      formatter: function (val) {
                          return   val + " %"
                      }
                  }
                }
                
              }
              
              var chart = new ApexCharts(
                document.querySelector("#ana_device"),
                options
              );
              
              chart.render();

                // console.log(cgraph);
                // console.log(tgraph);

              var options = {
                chart: {
                    height: 320,
                    type: 'area',
                    stacked: true,
                    toolbar: {
                      show: false,
                      autoSelected: 'zoom'
                    },
                },
                colors: ['#2a77f4', '#a5c2f1'],
                dataLabels: {
                    enabled: false
                },
                stroke: {
                    curve: 'smooth',
                    width: [1.5, 1.5],
                    dashArray: [0, 4],
                    lineCap: 'round',
                },
                grid: {
                  padding: {
                    left: 0,
                    right: 0
                  },
                  strokeDashArray: 3,
                },
                markers: {
                  size: 0,
                  hover: {
                    size: 0
                  }
                },
                series: [{
                    name: 'Cashout',
                    data: cgraph
                }, {
                    name: 'Transfers',
                    data: tgraph
                }],
              
                xaxis: {
                    type: 'month',
                    categories: ['Scenario 1', 'Scenario 2', 'Scenario 3', 'Scenario 4', 
                    'Scenario 5', 'Scenario 6', 'Scenario 7', 'Scenario 8', 
                    'Scenario 9', 'Scenario 10', 'Scenario 11', 'Scenario 12'],
                    axisBorder: {
                      show: true,
                    },  
                    axisTicks: {
                      show: true,
                    },                  
                },
                fill: {
                  type: "gradient",
                  gradient: {
                    shadeIntensity: 1,
                    opacityFrom: 0.4,
                    opacityTo: 0.3,
                    stops: [0, 90, 100]
                  }
                },
                
                tooltip: {
                    x: {
                        format: 'dd/MM/yy HH:mm'
                    },
                },
                legend: {
                  position: 'top',
                  horizontalAlign: 'right'
                },
              }
              
              var chart2 = new ApexCharts(
                document.querySelector("#ana_dash_1"),
                options
              );
              
              chart2.render();
        
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
        }
    });

}

$("#table_refresh a").click(function () {
    calculateDateRange();
});

function getItexBalance()
{
    $.ajax({
        type: "GET",
        url : "/tms/dashboard/getitex/balance",
        processData: false,
        contentType: false,

        success : function(json) {
            json = JSON.parse(json);
            var famt = json.accounts[0].availablebalance;
            $("#itexBal").text('₦ ' + famt);
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
            $("#itexBal").text('₦ 0.00');
        }
    });
}

function getKudaBalance()
{
    $.ajax({
        type: "GET",
        url : "/tms/dashboard/getkuda/balance",
        processData: false,
        contentType: false,

        success : function(json) {
            json = JSON.parse(json);
            var famt = (parseFloat(json.Data.AvailableBalance) / 100).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
            $("#kudaBal").text('₦ ' + famt);
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
            $("#kudaBal").text('₦ 0.00');
        }
    });
}

function getKudaBalance()
{
    $.ajax({
        type: "GET",
        url : "/tms/dashboard/getkuda/balance",
        processData: false,
        contentType: false,

        success : function(json) {
            json = JSON.parse(json);
            var famt = (parseFloat(json.Data.AvailableBalance) / 100).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
            $("#kudaBal").text('₦ ' + famt);
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
            $("#kudaBal").text('₦ 0.00');
        }
    });
}

function getWalletTotal()
{
    $.ajax({
        type: "GET",
        url : "/tms/dashboard/getwallets/balance",
        processData: false,
        contentType: false,

        success : function(json) {
            var wallets = json;
            var i = wallets.length - 1;
            var total = 0.00;
            for(; i > -1; i--) {
                total = parseFloat(total) + parseFloat(wallets[i].amount);
            }
            var famt = parseFloat(total).toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,');
            $("#allWallets").text('₦ ' + famt);
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
        }
    });
}

function getSignupCount()
{
    $.ajax({
        type: "GET",
        url : "/tms/dashboard/getsignup/count",
        processData: false,
        contentType: false,

        success : function(json) {
            $("#allUsers").text(json[0].exact_count);
            sgnCnt = json[0].exact_count;
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
        }
    });
}

function proceedPlease()
{
    getSignupCount();
    getWalletTotal();
    getKudaBalance();
    getItexBalance();
    calculateDateRange();
    getLatestSignup();
    getLatestFailed();
}

$(document).ready(function() {
    proceedPlease();
    setInterval(proceedPlease, 120*1000);
});