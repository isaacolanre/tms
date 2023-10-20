var record;
var edit = false;
var gId = 0;
var pending = null;

function gotoApprove(id)
{
    var use = "<p align=\"left\">";
    use += "TID: <span style=\"float:right;\">" + pending[id].tid + "</span></br>";
    use += "MID: <span style=\"float:right;\">" + pending[id].mid + "</span></br>";
    use += "SERIALNUMBER: <span style=\"float:right;\">" + pending[id].serialnumber + "</span></br>";
    use += "TERMINAL MODEL: <span style=\"float:right;\">" + pending[id].terminalmodel + "</span></br>";
    use += "INIT APP: <span style=\"float:right;\">" + pending[id].initapplicationversion + "</span></br>";
    use += "MERCHANT NAME: <span style=\"float:right;\">" + pending[id].merchantname + "</span></br>";
    use += "MERCHANT ADDRESS: <span style=\"float:right;\">" + pending[id].merchantaddress + "</span></br>";
    use += "ADMIN PIN: <span style=\"float:right;\">" + pending[id].adminpin + "</span></br>";
    use += "MERCHANT PIN: <span style=\"float:right;\">" + pending[id].merchantpin + "</span></br>";
    use += "CHANGE PIN: <span style=\"float:right;\">" + pending[id].changepin + "</span></br>";
    use += "ADDED BY: <span style=\"float:right;\">" + pending[id].addedby + "</span></br>";
    use += "CONTACT NAME: <span style=\"float:right;\">" + pending[id].contactname + "</span></br>";
    use += "CONTACT PHONE: <span style=\"float:right;\">" + pending[id].contactphone + "</span></br>";
    use += "EMAIL: <span style=\"float:right;\">" + pending[id].email + "</span></br>";
    use += "MCC: <span style=\"float:right;\">" + pending[id].mcc + "</span></br>";
    use += "DATE CREATED: <span style=\"float:right;\">" + pending[id].datecreated + "</span></br>";
    use += "NAME CREATED: <span style=\"float:right;\">" + pending[id].namecreated + "</span></br>";
    use += "LGA: <span style=\"float:right;\">" + pending[id].lga + "</span></br>";
    use += "APPNAME: <span style=\"float:right;\">" + pending[id].appname + "</span></br>";
    use += "COUNTRY: <span style=\"float:right;\">" + pending[id].country + "</span></br>";
    use += "COUNTRY CODE: <span style=\"float:right;\">" + pending[id].countrycode + "</span></br>";
    use += "PROFILE NAME: <span style=\"float:right;\">" + pending[id].profilename + "</span></br>";
    use += "PROFILE ID: <span style=\"float:right;\">" + pending[id].profileid + "</span></br>";
    use += "MANUFACTURER: <span style=\"float:right;\">" + pending[id].terminalmanufacturer + "</span></br>";
    use += "BLOCKED: <span style=\"float:right;\">" + pending[id].blocked + "</span></br>";
    use += "BLOCKED PIN: <span style=\"float:right;\">" + pending[id].blockedpin + "</span></br>";
    use += "OWNER USERNAME: <span style=\"float:right;\">" + pending[id].ownerusername + "</span></br>";
    use += "SUPER AGENT: <span style=\"float:right;\">" + pending[id].superagent + "</span></br>";
    use += "HEADING: <span style=\"float:right;\">" + pending[id].dialogheading + "</span></br>";
    use += "SIM SERIAL: <span style=\"float:right;\">" + pending[id].simserial + "</span></br>";
    use += "SIM NUMBER: <span style=\"float:right;\">" + pending[id].simnumber + "</span></br>";
    use += "SIM NAME: <span style=\"float:right;\">" + pending[id].simname + "</span></br>";
    use += "ACCOUNT NAME: <span style=\"float:right;\">" + pending[id].accountname + "</span></br>";
    use += "ACCOUNT CODE: <span style=\"float:right;\">" + pending[id].accountcode + "</span></br>";
    use += "ACCOUNT NUMBER: <span style=\"float:right;\">" + pending[id].accountnumber + "</span></br>";
    use += "ACCOUNT BANK: <span style=\"float:right;\">" + pending[id].accountbank + "</span></br>";
    use += "PTSP: <span style=\"float:right;\">" + pending[id].ptsp + "</span></br>";
    use += "BANK NAME: <span style=\"float:right;\">" + pending[id].bankname + "</span></br>";
    use += "BANK USERNAME: <span style=\"float:right;\">" + pending[id].bankusername + "</span></br>";
    use += "SUPER AGENT NAME: <span style=\"float:right;\">" + pending[id].saaccountname + "</span></br>";
    use += "SUPER AGENT CODE: <span style=\"float:right;\">" + pending[id].saaccountcode + "</span></br>";
    use += "SUPER AGENT ACT: <span style=\"float:right;\">" + pending[id].saaccountnumber + "</span></br>";
    use += "SUPER AGENT BANK: <span style=\"float:right;\">" + pending[id].saaccountbank + "</span></br>";
    use += "tms ACCOUNT NAME: <span style=\"float:right;\">" + pending[id].caaccountname + "</span></br>";
    use += "tms ACCOUNT CODE: <span style=\"float:right;\">" + pending[id].caaccountcode + "</span></br>";
    use += "tms ACCOUNT NUMBER: <span style=\"float:right;\">" + pending[id].caaccountnumber + "</span></br>";
    use += "tms BANK: <span style=\"float:right;\">" + pending[id].caaccountbank + "</span></br>";
    use += "tms FEE RULE: <span style=\"float:right;\">" + pending[id].tmsfeerule + "</span></br>";
    use += "SUPER AGENT FEE RULE: <span style=\"float:right;\">" + pending[id].superagentfeerule + "</span></br>";
    use += "MSC: <span style=\"float:right;\">" + pending[id].msc + "</span></br>";
    use += "SWITCH FEE: <span style=\"float:right;\">" + pending[id].switchfee + "</span></br>";
    use += "INSTANT VALUE: <span style=\"float:right;\">" + pending[id].instantvalue + "</span></br>";
    use += "INSTANT VALUE TIME: <span style=\"float:right;\">" + pending[id].instantvaluetime + "</span></br>";
    use += "INSTANT VALUE PERCENTAGE: <span style=\"float:right;\">" + pending[id].instantvaluepercentage + "</span></br>";
    use += "STAMP DUTY: <span style=\"float:right;\">" + pending[id].stampduty + "</span></br>";
    use += "tms TRANSFER RULE: <span style=\"float:right;\">" + pending[id].tmstransferrule + "</span></br>";
    use += "SUPER AGENT TRANSFER RULE: <span style=\"float:right;\">" + pending[id].superagenttransferrule + "</span></br>";
    use += "MAXIMUM AMOUNT: <span style=\"float:right;\">" + pending[id].maxamount + "</span></br>";
    use += "PERCENTAGE RULE: <span style=\"float:right;\">" + pending[id].percentagerule + "</span></br>";
    use += "SANEF NUMBER: <span style=\"float:right;\">" + pending[id].sanefnumber + "</span></br>";
    use += "TMO CODE: <span style=\"float:right;\">" + pending[id].tmo + "</span></br>";
    //start
    use += "SUPER AGGREGATOR ACCOUNT NAME: <span style=\"float:right;\">" + pending[id].superaccountname + "</span></br>";
    use += "SUPER AGGREGATOR ACCOUNT NUMBER: <span style=\"float:right;\">" + pending[id].superaccountnumber + "</span></br>";
    use += "SUPER AGGREGATOR BANK CODE: <span style=\"float:right;\">" + pending[id].superaccountcode + "</span></br>";
    use += "SUPER AGGREGATOR BANK NAME: <span style=\"float:right;\">" + pending[id].superbankname + "</span></br>";
    use += "SUPER AGGREGATOR PERCENTAGE: <span style=\"float:right;\">" + pending[id].superpercentage + "</span></br>";
    use += "MAXIMUM ABOUT BEFORE SWITCHING: <span style=\"float:right;\">" + pending[id].hostswitchamount + "</span></br>";
    
    use += "AGENT VTU PERCENTAGE: <span style=\"float:right;\">" + pending[id].vtu + "</span></br>";
    use += "AGENT DATA PERCENTAGE: <span style=\"float:right;\">" + pending[id].data + "</span></br>";
    use += "AGENT DISCOS PERCENTAGE: <span style=\"float:right;\">" + pending[id].discos + "</span></br>";
    use += "AGENT CABLE PERCENTAGE: <span style=\"float:right;\">" + pending[id].cable + "</span></br>";
    use += "AGENT INTERNET PERCENTAGE: <span style=\"float:right;\">" + pending[id].internet + "</span></br>";
    use += "AGENT EXAMINATION PERCENTAGE: <span style=\"float:right;\">" + pending[id].examination + "</span></br>";


    use += "INTERSWITCH TID: <span style=\"float:right;\">" + pending[id].iswtid + "</span></br>";
    use += "INTERSWITCH MID: <span style=\"float:right;\">" + pending[id].iswmid + "</span></br>";
    use += "WITHDRAWAL CAPPED: <span style=\"float:right;\">" + pending[id].wdcapped + "</span></br>";
    use += "WITHDRAWAL CAPPED SUPERAGENT: <span style=\"float:right;\">" + pending[id].wdsharesa + "</span></br>";
    use += "WITHDRAWAL CAPPED SUPER SUPER: <span style=\"float:right;\">" + pending[id].wdsharess + "</span></br>";
    use += "CARD TRANSFER CREDIT ASSIST: <span style=\"float:right;\">" + pending[id].cttms + "</span></br>";
    use += "CARD TRANSFER SUPER AGENT: <span style=\"float:right;\">" + pending[id].ctsuperagent + "</span></br>";
    use += "CARD TRANSFER SUPER SUPER: <span style=\"float:right;\">" + pending[id].ctsupersuperagent + "</span></br>";
    use += "WALLET TRANSFER SUPER SUPER: <span style=\"float:right;\">" + pending[id].wtsupersuper + "</span></br>";
    
    //end
    use += "</p>";
    
    swal({
        title: "Approve or Delete?",
        html: use,
        //text: use,
        type: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#800080',
        cancelButtonColor: '#001e33',
        confirmButtonText: 'Yes, Approve!',
        confirmButtonClass: "btn-danger",
        cancelButtonText: "No, Delete!",
        allowOutsideClick: "true" 
    }).then(function (result) {
        if (result.value) {
            swal({
                title: "Processing...",
                text: "Please wait",
                showConfirmButton: false,
                allowOutsideClick: false
            });
            var fd = new FormData();
            $.ajax({
                type: "PUT",
                url : "/tms/pending/copyclone/terminalconfigurationclone/" + pending[id].id,
                data : fd,
                processData: false,
                contentType: false,
        
                success : function(json) {
                    swal(
                        'Done!',
                        "Changes Approved....",
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
                        "Error Occurred",
                        'error'
                    );
                }
            });
        }else
        {
            swal({
                title: "Processing...",
                text: "Please wait",
                showConfirmButton: false,
                allowOutsideClick: false
            });
            var fd = new FormData();
            $.ajax({
                type: "PUT",
                url : "/tms/pending/deleteclone/terminalconfigurationclone/" + pending[id].id,
                data : fd,
                processData: false,
                contentType: false,
        
                success : function(json) {
                    swal(
                        'Done!',
                        "Changes Declined....",
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
                        "Error Occurred",
                        'error'
                    );
                }
            });
        }
    });
}

function parseResponse()
{
    if(pending === null)
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
        var i = pending.length - 1;
        for(; i > -1; i--) {
            arr = [];
            arr.push("TERMINAL SETTINGS");
            arr.push(pending[i].namecreated + " just made changes to " + pending[i].tid + ". Kindly Approve or Delete.");
            arr.push("<button onclick=\"gotoApprove('" + i + "');\" type=\"button\" class=\"btn btn-success\">View</button>");
            $('#datatable-buttons').DataTable().row.add(arr);
        }
        $('#datatable-buttons').DataTable().draw();
    }
}

function getAPendingTerminals()
{
    $.ajax({
        type: "GET",
        url : "/tms/pending/getoutstanding/terminalconfigurationclone",
        processData: false,
        contentType: false,

        success : function(json) {
            pending = JSON.parse(json.message);
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
    getAPendingTerminals();
});