var record;
var edit = false;
var gId = 0;

var update = 0;
var sendId = 0;
var idval = 0;
var labval = 0;

$("#newclicked").click(function(){
    $("#tmsform").show();
    $("#tmstable").hide();
    idval = 0;
    labval = 0;
 });

 $("#backclicked").click(function(){
    update = 0;
    $("#tmsform").hide();
    $("#tmstable").show();
    $("#name").val("");
    $("#vendorid").val("");
    $("#conveniencefee").val("");
    idval = 0;
 });

function removeLabel(id)
{
    var temp = parseInt(id) + 1;
    if(temp !== labval)
    {
        swal(
            'Info!',
            'Delete the last Label',
            'info'
        );
    }else
    {
        $('#ldiv' + id).remove(); 
        labval--;
    }
}

$("#newLabelClick").click(function()
{
    var use = "<div id=ldiv" + labval.toString() + ">"
    use += "<div class=\"form-group\">";
    use += "<label class=\"control-label col-md-3 col-sm-3 col-xs-12\" for=\"first-name\">Name <span class=\"required\">*</span></label>";
    use += "<div class=\"col-md-6 col-sm-6 col-xs-12\">";
    use += "<input type=\"text\" id=\"lname" + labval.toString() + "\" required=\"required\" class=\"form-control col-md-7 col-xs-12\"></div></div>";
    
    use += "<div class=\"form-group\">";
    use += "<label class=\"control-label col-md-3 col-sm-3 col-xs-12\" for=\"first-name\">Value <span class=\"required\">*</span></label>";
    use += "<div class=\"col-md-6 col-sm-6 col-xs-12\">";
    use += "<input type=\"text\" id=\"lval" + labval.toString() + "\" class=\"form-control col-md-7 col-xs-12\"></div></div>";
    
    use += "<div class=\"form-group\"><label class=\"control-label col-md-3 col-sm-3 col-xs-12\" for=\"first-name\">Input Type <span class=\"required\">*</span></label><div class=\"col-md-6 col-sm-6 col-xs-12\">";
    use += "<select id=\"intype" + labval.toString() + "\" class=\"form-control col-md-7 col-xs-12\">";
    use += "<option value=\"alphabet\">Alphabet</option>";
    use += "<option value=\"numeric\">Numeric</option>";
    use += "<option value=\"alphanumeric\">Alphanumeric</option>";
    use += "<option value=\"alphanumericspecial\">Alphanumeric + Special Characters</option>";
    use += "</select></div></div>";
    
    use += "<div class=\"form-group\">";
    use += "<label class=\"control-label col-md-3 col-sm-3 col-xs-12\" for=\"first-name\">Length Rule <span class=\"required\">*</span></label>";
    use += "<div class=\"col-md-6 col-sm-6 col-xs-12\">";
    use += "<input type=\"text\" id=\"llen" + labval.toString() + "\" required=\"required\" class=\"form-control col-md-7 col-xs-12\"></div></div>";
    
    use += "<div class=\"form-group\"><label class=\"control-label col-md-3 col-sm-3 col-xs-12\" for=\"first-name\">Revalidate <span class=\"required\">*</span></label><div class=\"col-md-6 col-sm-6 col-xs-12\">";
    use += "<select id=\"revalid" + labval.toString() + "\" class=\"form-control col-md-7 col-xs-12\">";
    use += "<option value=\"true\">True</option>";
    use += "<option value=\"false\">False</option>";
    use += "</select></div></div>";
    
    use += "<div class=\"form-group\"><label class=\"control-label col-md-3 col-sm-3 col-xs-12\" for=\"first-name\">Capture Token <span class=\"required\">*</span></label><div class=\"col-md-6 col-sm-6 col-xs-12\">";
    use += "<select id=\"captoken" + labval.toString() + "\" class=\"form-control col-md-7 col-xs-12\">";
    use += "<option value=\"true\">True</option>";
    use += "<option value=\"false\">False</option>";
    use += "</select></div></div>";

    use += "<div class=\"form-group\"><label class=\"control-label col-md-3 col-sm-3 col-xs-12\" for=\"first-name\">Print Value <span class=\"required\">*</span></label><div class=\"col-md-6 col-sm-6 col-xs-12\">";
    use += "<select id=\"printval" + labval.toString() + "\" class=\"form-control col-md-7 col-xs-12\">";
    use += "<option value=\"true\">True</option>";
    use += "<option value=\"false\">False</option>";
    use += "</select></div></div>";
    
    use += "<div class=\"form-group\"><div class=\"col-md-6 col-sm-6 col-xs-12 col-md-offset-3\">";
    use += "<button onclick=\"removeLabel('" + labval.toString() + "');\" type=\"button\" class=\"btn btn-success\">Remove</button></div></div>";

    use += "<hr></div>";
    labval++;
    $('#labBtn').append(use);
});

function removeClick(id)
{
    var temp = parseInt(id) + 1;
    if(temp !== idval)
    {
        swal(
            'Info!',
            'Delete the last Product',
            'info'
        );
    }else
    {
        $('#pdiv' + id).remove(); 
        idval--;
    }
}

$("#newProductClick").click(function()
{
    var use = "<div id=pdiv" + idval.toString() + ">";
    use += "<label class=\"control-label col-md-3 col-sm-3 col-xs-12\" for=\"first-name\">Name <span class=\"required\">*</span></label>";
    use += "<div class=\"col-md-6 col-sm-6 col-xs-12\">";
    use += "<input type=\"text\" id=\"pname" + idval.toString() + "\" required=\"required\" class=\"form-control col-md-7 col-xs-12\"></div>";
    use += "<hr><hr><hr>";

    use += "<label class=\"control-label col-md-3 col-sm-3 col-xs-12\" for=\"first-name\">Amount (NGN) <span class=\"required\">*</span></label>";
    use += "<div class=\"col-md-6 col-sm-6 col-xs-12\">";
    use += "<input type=\"text\" id=\"pamt" + idval.toString() + "\" required=\"required\" class=\"form-control col-md-7 col-xs-12\"></div>";
    use += "<hr><hr><hr>";

    use += "<div class=\"form-group\"><div class=\"col-md-6 col-sm-6 col-xs-12 col-md-offset-3\">";
    use += "<button onclick=\"removeClick('" + idval.toString() + "');\" type=\"button\" class=\"btn btn-success\">Remove</button></div>";

    use += "<hr></div>";
    idval++;
    $('#proBtn').append(use);
});

function editFormProduct(products)
{
    var jsonData = JSON.parse(products);
    for(var i = 0; i < jsonData.length; i++) 
    {
        var use = "<div id=pdiv" + idval.toString() + ">";
        use += "<label class=\"control-label col-md-3 col-sm-3 col-xs-12\" for=\"first-name\">Name <span class=\"required\">*</span></label>";
        use += "<div class=\"col-md-6 col-sm-6 col-xs-12\">";
        use += "<input type=\"text\" id=\"pname" + idval.toString() + "\" required=\"required\" class=\"form-control col-md-7 col-xs-12\"></div>";
        use += "<hr><hr><hr>";

        use += "<label class=\"control-label col-md-3 col-sm-3 col-xs-12\" for=\"first-name\">Amount (NGN) <span class=\"required\">*</span></label>";
        use += "<div class=\"col-md-6 col-sm-6 col-xs-12\">";
        use += "<input type=\"text\" id=\"pamt" + idval.toString() + "\" required=\"required\" class=\"form-control col-md-7 col-xs-12\"></div>";
        use += "<hr><hr><hr>";

        use += "<div class=\"form-group\"><div class=\"col-md-6 col-sm-6 col-xs-12 col-md-offset-3\">";
        use += "<button onclick=\"removeClick('" + idval.toString() + "');\" type=\"button\" class=\"btn btn-success\">Remove</button></div>";
        
        use += "<hr></div>";
    
        idval++;
        $('#proBtn').append(use);
        $("#pname" + i.toString()).val(jsonData[i].productname);
        $("#pamt" + i.toString()).val(jsonData[i].value);
    }
}

function editFormLabel(labels)
{
    var jsonData = JSON.parse(labels);
    for(var i = 0; i < jsonData.length; i++) 
    {
        var use = "<div id=ldiv" + labval.toString() + ">"
        use += "<div class=\"form-group\">";
        use += "<label class=\"control-label col-md-3 col-sm-3 col-xs-12\" for=\"first-name\">Name <span class=\"required\">*</span></label>";
        use += "<div class=\"col-md-6 col-sm-6 col-xs-12\">";
        use += "<input type=\"text\" id=\"lname" + labval.toString() + "\" required=\"required\" class=\"form-control col-md-7 col-xs-12\"></div></div>";
        
        use += "<div class=\"form-group\">";
        use += "<label class=\"control-label col-md-3 col-sm-3 col-xs-12\" for=\"first-name\">Value <span class=\"required\">*</span></label>";
        use += "<div class=\"col-md-6 col-sm-6 col-xs-12\">";
        use += "<input type=\"text\" id=\"lval" + labval.toString() + "\" class=\"form-control col-md-7 col-xs-12\"></div></div>";
        
        use += "<div class=\"form-group\"><label class=\"control-label col-md-3 col-sm-3 col-xs-12\" for=\"first-name\">Input Type <span class=\"required\">*</span></label><div class=\"col-md-6 col-sm-6 col-xs-12\">";
        use += "<select id=\"intype" + labval.toString() + "\" class=\"form-control col-md-7 col-xs-12\">";
        use += "<option value=\"alphabet\">Alphabet</option>";
        use += "<option value=\"numeric\">Numeric</option>";
        use += "<option value=\"alphanumeric\">Alphanumeric</option>";
        use += "<option value=\"alphanumericspecial\">Alphanumeric + Special Characters</option>";
        use += "</select></div></div>";
        
        use += "<div class=\"form-group\">";
        use += "<label class=\"control-label col-md-3 col-sm-3 col-xs-12\" for=\"first-name\">Length Rule <span class=\"required\">*</span></label>";
        use += "<div class=\"col-md-6 col-sm-6 col-xs-12\">";
        use += "<input type=\"text\" id=\"llen" + labval.toString() + "\" required=\"required\" class=\"form-control col-md-7 col-xs-12\"></div></div>";
        
        use += "<div class=\"form-group\"><label class=\"control-label col-md-3 col-sm-3 col-xs-12\" for=\"first-name\">Revalidate <span class=\"required\">*</span></label><div class=\"col-md-6 col-sm-6 col-xs-12\">";
        use += "<select id=\"revalid" + labval.toString() + "\" class=\"form-control col-md-7 col-xs-12\">";
        use += "<option value=\"true\">True</option>";
        use += "<option value=\"false\">False</option>";
        use += "</select></div></div>";
        
        use += "<div class=\"form-group\"><label class=\"control-label col-md-3 col-sm-3 col-xs-12\" for=\"first-name\">Capture Token <span class=\"required\">*</span></label><div class=\"col-md-6 col-sm-6 col-xs-12\">";
        use += "<select id=\"captoken" + labval.toString() + "\" class=\"form-control col-md-7 col-xs-12\">";
        use += "<option value=\"true\">True</option>";
        use += "<option value=\"false\">False</option>";
        use += "</select></div></div>";

        use += "<div class=\"form-group\"><label class=\"control-label col-md-3 col-sm-3 col-xs-12\" for=\"first-name\">Print Value <span class=\"required\">*</span></label><div class=\"col-md-6 col-sm-6 col-xs-12\">";
        use += "<select id=\"printval" + labval.toString() + "\" class=\"form-control col-md-7 col-xs-12\">";
        use += "<option value=\"true\">True</option>";
        use += "<option value=\"false\">False</option>";
        use += "</select></div></div>";
        
        use += "<div class=\"form-group\"><div class=\"col-md-6 col-sm-6 col-xs-12 col-md-offset-3\">";
        use += "<button onclick=\"removeLabel('" + labval.toString() + "');\" type=\"button\" class=\"btn btn-success\">Remove</button></div></div>";

        use += "<hr></div>";
        labval++;
        $('#labBtn').append(use);

        $("#lname" + i.toString()).val(jsonData[i].labelname);
        $("#lval" + i.toString()).val(jsonData[i].value);
        $("#intype" + i.toString()).val(jsonData[i].inputtype.toString()).change();
        $("#llen" + i.toString()).val(jsonData[i].lengthrule);
        $("#revalid" + i.toString()).val(jsonData[i].revalidate.toString()).change();
        $("#captoken" + i.toString()).val(jsonData[i].capturetoken.toString()).change();
        $("#printval" + i.toString()).val(jsonData[i].printvalue.toString()).change();
    }
}

function gotoEdit(id)
{
    var jsonData = record;
    var cat = id;
    sendId = jsonData[cat].id;
    
    edit = true;
    gId = record[id].id;
    $("#tmsform").show();
    $("#tmstable").hide();
     
    idval = 0;
    labval = 0;
    $("#name").val(jsonData[cat].billername);
    $("#vendorid").val(jsonData[cat].vendorid);
    $("#istoken").val(jsonData[cat].istoken.toString()).change();
    $("#printall").val(jsonData[cat].printall.toString()).change();
    $("#conveniencefee").val(jsonData[cat].conveniencefee);
    $("#printvalidation").val(jsonData[cat].printvalidation.toString()).change();
    editFormProduct(jsonData[cat].products);
    editFormLabel(jsonData[cat].labels);
    update = 2;
}

var chprod = [];
var proname = [];
function formProducts()
{
    var lab = [];
    proname = [];
    for(var i = 0; i < idval; i++)
    {
        var obj = new Object();
        obj.productname = $("#pname" + i.toString()).val();
        proname.push(obj.productname);
        obj.value = $("#pamt" + i.toString()).val();
        lab.push(obj);
    }
    chprod = lab;
    return JSON.stringify(lab);
}

var chlabel = [];
var labname = [];
function formLabels()
{
    var lab = [];
    labname = [];
    for(var i = 0; i < labval; i++)
    {
        var obj = new Object();
        obj.labelname = $("#lname" + i.toString()).val();
        labname.push(obj.labelname);
        obj.value = $("#lval" + i.toString()).val();
        obj.inputtype = $("#intype" + i.toString()).val();
        obj.lengthrule = $("#llen" + i.toString()).val();
        obj.revalidate = $("#revalid" + i.toString()).val();
        obj.capturetoken = $("#captoken" + i.toString()).val();
        obj.printvalue = $("#printval" + i.toString()).val();
        lab.push(obj);
    }
    chlabel = lab;
    return JSON.stringify(lab);
}

$("#demo-form2" ).submit(function( event ) {
    event.preventDefault();
    $("#btnsend").hide();
    
    var fd = new FormData();
    fd.append('billername', $("#name").val());
    fd.append('vendorid', $("#vendorid").val());
    fd.append('istoken', $("#istoken").val());
    fd.append('printall', $("#printall").val());
    fd.append('conveniencefee', $("#conveniencefee").val());
    fd.append('printvalidation', $("#printvalidation").val());
    fd.append('labels', formLabels());
    fd.append('products', formProducts());
    
    var count = 0;
    for(var i = 0; i < chprod.length; i++)
    {
        for (var j = 0; j < proname.length; j++) 
        {
            if (proname[j] === chprod[i].productname)
                count++;
        };
        if(count > 1)
        {
            swal(
                'Error!',
                "Product " + chprod[i].productname + " already exist",
                'error'
            );
            $("#payment-button").show();
            return;
        }else
        {
            count = 0;
        }
    }
    
    count = 0;
    for(var i = 0; i < chlabel.length; i++)
    {
        for (var j = 0; j < labname.length; j++) 
        {
            if (labname[j] === chlabel[i].labelname)
                count++;
        };
        if(count > 1)
        {
            swal(
                'Error!',
                "Label " + chlabel[i].labelname + " already exist",
                'error'
            );
            $("#payment-button").show();
            return;
        }else
        {
            count = 0;
        }
    }
    
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
        url : "/tms/billing/show",
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
        text: "Are you sure you want to delete " + record[id].billername + "?",
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
                url : "/tms/billing/deletedata/" + record[id].id,
                data : fd,
                processData: false,
                contentType: false,
        
                success : function(json) {
                    swal(
                        'Done!',
                        record[id].billername + " deleted.",
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
                        record[id].billername + " not deleted.",
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
            arr.push(record[i].billername);
            arr.push(record[i].vendorid);
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
        url : "/tms/billing/getalldata",
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