var record;
var banks = null;
var comms = null;
var receipt = null;
var logo = null;
var callhome = null;
var host = null;
var hostkeys = null;
var vas = null;
var currency = null;
var trans = null;
var edit = false;
var gId = 0;
var txn = "";
var pro = "";
var hos = "";

$("#newclicked").click(function(){
    $("#tmsform").show();
    $("#tmstable").hide();
 });

 $("#backclicked").click(function(){
    $("#tmsform").hide();
    $("#tmstable").show();
    $("#name").val("");
    $("#remarks").val("");
    edit = false;
    gId = 0;
 });

$("#demo-form2" ).submit(function( event ) {
    event.preventDefault();

    var jsonData2 = trans;
    for(var i = (jsonData2.length - 1); i >= 0; i-- ) {
        if($('#txn' + jsonData2[i].id + ':checkbox:checked').length)
        {
            txn += jsonData2[i].id + '#';
        }
		//New
		if($('#pro' + jsonData2[i].id + ':checkbox:checked').length)
        {
            pro += jsonData2[i].id + '#';
        }
        //Host
        if($('#hos' + jsonData2[i].id + ':checkbox:checked').length)
        {
            hos += jsonData2[i].id + ' - h1' + '#';
        }else
        {
            hos += jsonData2[i].id  + ' - h2' + '#';
        }
    }

    $("#btnsend").hide();
    var fd = new FormData();
    fd.append('name', $("#name").val());
    fd.append('remarks', $("#remarks").val());
    fd.append('bankid', $("#banks").val());
    fd.append('commsid', $("#communications").val());
    fd.append('receiptid', $("#receipt").val());
    fd.append('rlogoid', $("#receiptlogo").val());
    fd.append('blogoid', $("#backgroundlogo").val());
    fd.append('callhomeid', $("#callhome").val());
    fd.append('hostid', $("#emvhost").val());
    fd.append('host2id', $("#ussdhost").val());
    fd.append('switchkeyid', $("#emvhostkeys").val());
    fd.append('fswitchkeyid', $("#ussdhostkeys").val());
    fd.append('currencyid', $("#currency").val());
    fd.append('transactiontypesarray', txn);
    fd.append('protectlist', pro);
    fd.append('hostarray', hos);
    fd.append('tmspay', $("#tmspay").val());
    fd.append('cardschemekeytypes', $("#cardtype").val());
    fd.append('billsmenu', $("#vas").val());
    fd.append('edit', edit);
    fd.append('id', gId);

    $.ajax({
        type: "POST",
        url : "/tms/profile/show",
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

function gotoEdit(id)
{
    edit = true;
    gId = record[id].id;
    //Start here
    $("#tmsform").show();
    $("#tmstable").hide();

    $("#name").val(record[id].name);
    $("#remarks").val(record[id].remarks);
    if(record[id].bankid)
        $("#banks").val(record[id].bankid.toString()).change();
    if(record[id].commsid)
        $("#communications").val(record[id].commsid.toString()).change();
    if(record[id].receiptid)
        $("#receipt").val(record[id].receiptid.toString()).change();
    if(record[id].rlogoid)
        $("#receiptlogo").val(record[id].rlogoid.toString()).change();
    if(record[id].blogoid)
        $("#backgroundlogo").val(record[id].blogoid.toString()).change();
    if(record[id].callhomeid)
        $("#callhome").val(record[id].callhomeid.toString()).change();
    if(record[id].hostid)
        $("#emvhost").val(record[id].hostid.toString()).change();
    if(record[id].host2id)
        $("#ussdhost").val(record[id].host2id.toString()).change();
    if(record[id].switchkeyid)
        $("#emvhostkeys").val(record[id].switchkeyid.toString()).change();
    if(record[id].fswitchkeyid)
        $("#ussdhostkeys").val(record[id].fswitchkeyid.toString()).change();
    if(record[id].currencyid)
        $("#currency").val(record[id].currencyid.toString()).change();
    if(record[id].billsmenu)
        $("#vas").val(record[id].billsmenu.toString()).change();
    if(record[id].cardschemekeytypes)
        $("#cardtype").val(record[id].cardschemekeytypes.toString()).change();
    if(record[id].tmspay)  
        $("#tmspay").val(record[id].tmspay.toString()).change();


    t = record[id].transactiontypesarray;
	z = record[id].protectlist;
    ha = record[id].hostarray;
    
    var arry = [];
	var ar = "";
	for(var j = 0; j < t.length; j++)
	{
		if(t.charAt(j) === '#')
		{
			arry.push(ar);
			ar = "";
		}else
		{
			ar += t.charAt(j);
		}
	}
	
	var arry2 = [];
    var ar2 = "";
	if(z)
	{
		for(var j = 0; j < z.length; j++)
		{
			if(z.charAt(j) === '#')
			{
				arry2.push(ar2);
				ar2 = "";
			}else
			{
				ar2 += z.charAt(j);
			}
		}
	}

    var arry3 = [];
    var arry4 = [];
    var ar3 = "";
    var ar4 = "";
    var loop = 0;
    if(ha)
	{
		for(var j = 0; j < ha.length; j++)
		{
			if(ha.charAt(j) === '#')
			{
                loop = 0;
				arry4.push(ar4);
				ar4 = "";
			}else if(ha.charAt(j) === ' ')
			{
                loop = 1;
				arry3.push(ar3);
                ar3 = "";
                j += 2;
			}else
			{
                if(loop === 0)
                {
                    ar3 += ha.charAt(j);
                }else
                {
                    ar4 += ha.charAt(j);
                }
			}
		}
	}
    
    for(var j = 0; j < arry4.length; j++) {
        var ch = arry4[j];
        if(ch === "h2")
            $('#hos' + arry3[j]).removeAttr('checked');
        else
			$('#hos' + arry3[j]).prop('checked', 'checked');
    }
    var jsonData2 = trans;
    for(var i = (jsonData2.length - 1); i >= 0; i-- ) {
		$('#txn' + jsonData2[i].id).prop('checked', 'checked');
    }
    
    var num = 0;	


    

    for(var j = (jsonData2.length - 1); j >= 0; j-- ) {
		num = jsonData2[j].id;
		if(arry.indexOf(num.toString()) == -1)
            $('#txn' + jsonData2[j].id).removeAttr('checked');
		//New
		if(arry2.indexOf(num.toString()) !== -1)
            $('#pro' + jsonData2[j].id).prop('checked', 'checked');
        else
        {
            $('#pro' + jsonData2[j].id).removeAttr('checked');
        }
    }
}


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
                url : "/tms/profile/deleteprofile/" + record[id].id,
                data : fd,
                processData: false,
                contentType: false,
        
                success : function(json) {
                    swal(
                        'Done!',
                        record[id].name + " is deleted.",
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

function processTrans()
{
    if(trans === null)
    {
        //Do nothing because it is null
    }else
    {
        var i = trans.length - 1;
        for(; i > -1; i--) {
            $("#transact").append("<input style=\"margin-left: 20px; margin-right: 80px;\" id=\"hos" + trans[i].id + "\" type=\"checkbox\" class=\"flat\" checked/>");
            $("#transact").append("<input style=\"margin-right: 60px;\" id=\"pro" + trans[i].id + "\" type=\"checkbox\" class=\"flat\" checked/>");
            $("#transact").append("<input style=\"margin-right: 55px;\" id=\"txn" + trans[i].id + "\" type=\"checkbox\" class=\"flat\" checked/>");
            $("#transact").append("<label for=\"cc-payment\" class=\"control-label mb-1\">" + trans[i].name + "</label><br><br></br>");
        }
    }
}

function getAllTrans()
{
    $.ajax({
        type: "GET",
        url : "/tms/transactiontypes/getalldata",
        processData: false,
        contentType: false,

        success : function(json) {
            trans = JSON.parse(json.message);
            processTrans();
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
        }
    });
}

function processCurrency()
{
    if(currency === null)
    {
        //Do nothing because it is null
    }else
    {
        var i = currency.length - 1;
        for(; i > -1; i--) {
            $("#currency").append('<option value=' + currency[i].id + '>' + currency[i].name + '</option');
        }
    }
}

function getAllCurrency()
{
    $.ajax({
        type: "GET",
        url : "/tms/currency/getalldata",
        processData: false,
        contentType: false,

        success : function(json) {
            currency = JSON.parse(json.message);
            processCurrency();
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
        }
    });
}

function processBills()
{
    if(vas === null)
    {
        //Do nothing because it is null
    }else
    {
        var i = vas.length - 1;
        for(; i > -1; i--) {
            $("#vas").append('<option value=' + vas[i].id + '>' + vas[i].billmenuname + '</option');
        }
    }
}

function getAllBills()
{
    $.ajax({
        type: "GET",
        url : "/tms/billing/menudata",
        processData: false,
        contentType: false,

        success : function(json) {
            vas = JSON.parse(json.message);
            processBills();
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
        }
    });
}

function processHostKeys()
{
    if(hostkeys === null)
    {
        //Do nothing because it is null
    }else
    {
        var i = hostkeys.length - 1;
        for(; i > -1; i--) {
            $("#emvhostkeys").append('<option value=' + hostkeys[i].id + '>' + hostkeys[i].name + '</option');
            $("#ussdhostkeys").append('<option value=' + hostkeys[i].id + '>' + hostkeys[i].name + '</option');
        }
    }
}

function getAllHostKeys()
{
    $.ajax({
        type: "GET",
        url : "/tms/hostkeys/getallhostkeys",
        processData: false,
        contentType: false,

        success : function(json) {
            hostkeys = JSON.parse(json.message);
            processHostKeys();
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
        }
    });
}

function processHost()
{
    if(host === null)
    {
        //Do nothing because it is null
    }else
    {
        var i = host.length - 1;
        for(; i > -1; i--) {
            $("#emvhost").append('<option value=' + host[i].id + '>' + host[i].name + '</option');
            $("#ussdhost").append('<option value=' + host[i].id + '>' + host[i].name + '</option');
        }
    }
}

function getAllHost()
{
    $.ajax({
        type: "GET",
        url : "/tms/settings/getallhosts",
        processData: false,
        contentType: false,

        success : function(json) {
            host = JSON.parse(json.message);
            processHost();
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
        }
    });
}

function processCallhome()
{
    if(callhome === null)
    {
        //Do nothing because it is null
    }else
    {
        var i = callhome.length - 1;
        for(; i > -1; i--) {
            $("#callhome").append('<option value=' + callhome[i].id + '>' + callhome[i].name + '</option');
        }
    }
}

function getAllCallhome()
{
    $.ajax({
        type: "GET",
        url : "/tms/settings/getallcallhomes",
        processData: false,
        contentType: false,

        success : function(json) {
            callhome = JSON.parse(json.message);
            processCallhome();
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
        }
    });
}

function processLogo()
{
    if(logo === null)
    {
        //Do nothing because it is null
    }else
    {
        var i = logo.length - 1;
        for(; i > -1; i--) {
            if(logo[i].isreceipt === "true")
                $("#receiptlogo").append('<option value=' + logo[i].id + '>' + logo[i].bankname + '</option');
            else
                $("#backgroundlogo").append('<option value=' + logo[i].id + '>' + logo[i].bankname + '</option');
        }
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
            logo = JSON.parse(json.message);
            processLogo();
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
        }
    });
}

function processReceipt()
{
    if(receipt === null)
    {
        //Do nothing because it is null
    }else
    {
        var i = receipt.length - 1;
        for(; i > -1; i--) {
            $("#receipt").append('<option value=' + receipt[i].id + '>' + receipt[i].name + '</option');
        }
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
            receipt = JSON.parse(json.message);
            processReceipt();
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
        }
    });
}

function processComms()
{
    if(comms === null)
    {
        //Do nothing because it is null
    }else
    {
        var i = comms.length - 1;
        for(; i > -1; i--) {
            $("#communications").append('<option value=' + comms[i].id + '>' + comms[i].name + '</option');
        }
    }
}

function getAllComms()
{
    $.ajax({
        type: "GET",
        url : "/tms/settings/getallcomms",
        processData: false,
        contentType: false,

        success : function(json) {
            comms = JSON.parse(json.message);
            processComms();
        },

        complete: function(){
            
        },
        
        error : function(xhr,errmsg,err) {
            console.log(xhr.responseText);
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
            banks = JSON.parse(json.message);
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
            arr.push(record[i].name);
            arr.push(record[i].id);
            //arr.push(record[i].tmspay);
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
        url : "/tms/profile/getalldata",
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
    getAllBanks();
    getAllComms();
    getAllReceipt();
    getAllLogo();
    getAllCallhome();
    getAllHost();
    getAllHostKeys();
    getAllBills();//Take note, not implemented
    getAllCurrency();
    getAllTrans();
});