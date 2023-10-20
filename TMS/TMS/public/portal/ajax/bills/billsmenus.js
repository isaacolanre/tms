var record;
var bills;
var edit = false;
var gId = 0;

var arrayJsTree = [];

var update = 0;
var sendId = 0;

$("#newclicked").click(function(){
    update = 1;
    $("#tmsform").show();
    $("#tmstable").hide();
    $("#name").val("");
    arrayJsTree = JSON.parse("[{ \"text\" : \"PAYMENT\", \"children\" : []}]");
    $('#jstree_demo_div').jstree("destroy").empty();
    $(function() {
        $('#jstree_demo_div').jstree(
        {
            "core" : 
            {
                strings : {
                    'New node': 'Category'
                },
                "animation" : 0,
                "check_callback" : true,
                "themes" : 
                { 
                    "stripes" : true 
                },
    
                'data':  arrayJsTree,
            },
            "types" : 
            {
                "#" : 
                {
                    "max_children" : 1,
                    "max_depth" : 1000,
                    "valid_children" : ["root"]
                },
                "root" : 
                {
                    "icon" : "/portal/ajax/bills/treeicon.png",
                    "valid_children" : ["default","category", "biller"]
                },
                "default" : 
                {
                    "valid_children" : ["default","category", "biller"]
                },
                "category" : 
                {
                    "icon" : "/portal/ajax/bills/treeicon.png",
                    "valid_children" : ["default","category", "biller"]
                },
                "biller" : 
                {
                    "icon" : "/portal/ajax/bills/biller.png",
                    "valid_children" : ["default"]
                }
            },
            "plugins" : [
                "contextmenu", "dnd", "search",
                "state", "types", "wholerow"
            ],
            "contextmenu":{
                "items": function () {
                    return {
                        "Create": {
                            "label": "Add Category",
                            "icon" : "/portal/ajax/bills/treeicon.png",
                            "action": function (data) {
                                var inst = $.jstree.reference(data.reference);
                                    obj = inst.get_node(data.reference);
                                if(obj.original.type === 'biller')
                                {
                                    swal(
                                        'Warning',
                                        'You can not add a category in a biller',
                                        'info'
                                    );
                                    return;
                                }else
                                {
                                    var ref = $.jstree.reference(data.reference);
                                        sel = ref.get_selected();
                                    if(!sel.length) { return false; }
                                    sel = sel[0];
                                    sel = ref.create_node(sel, {"type":"category"});
                                    if(sel) {
                                        ref.edit(sel);
                                    }
                                }
                            }
                        },
                        "Biller": {
                            "label": "Add Biller",
                            "icon" : "/portal/ajax/bills/biller.png",
                            "action": function (data) {
                                var inst = $.jstree.reference(data.reference);
                                    obj = inst.get_node(data.reference);
                                if(obj.original.type === 'biller')
                                {
                                    swal(
                                        'Warning',
                                        'You can not add a biller in another biller',
                                        'info'
                                    );
                                    return;
                                }else
                                {
                                    var ref = $.jstree.reference(data.reference);
                                        sel = ref.get_selected();
                                    if(!sel.length) { return false; }
                                    sel = sel[0];
    
                                    var jsonData = bills;
                                    var use = "<div class=\"form-group\">";
                                    use += "<label for=\"cc-ssl\" class=\"control-label mb-1\">All Billers</label>";
                                    use += "<select style=\"color: #001e33; font-weight: bold;\" name=\"cc-ssl\" id=\"listbillers\" class=\"form-control\">";
                                    //console.log(jsonData);
                                    for(var i = 0; i < jsonData.length; i++) {
                                        //console.log(jsonData[i].billername);
                                        use += "<option style=\"color: #001e33; font-weight: bold;\" value=\"" + jsonData[i].billername + "\">" + jsonData[i].billername + "</option>";
                                    }
                                    use += "</select></div>";
    
                                    var myhtml = document.createElement("div");
                                    myhtml.innerHTML = use;
                                    swal({
                                        title: "Billers",
                                        content: myhtml,
                                        icon: "success",
                                        buttons: {
                                        label: "Add Selected",
                                        remove: "Close"
                                        }
                                    }).then((value) => {
                                        switch (value) {
                                            case "label":
                                                var bilname = $("#listbillers").val();
                                                sel = ref.create_node(sel, {"type":"biller", "text": bilname});
                                                if(sel) {
                                                    ref.edit(sel);
                                                }
                                                break;
                                            case "remove":
                                            default:
                                                break;
                                        }
                                    });
                                }
                            }
                        },
                        "Rename": {
                            "label": "Rename",
                            "icon" : "/portal/ajax/bills/rename.png",
                            "action": function (data) {
                                var inst = $.jstree.reference(data.reference);
                                    obj = inst.get_node(data.reference);
                                inst.edit(obj);
                            }
                        },
                        "Delete": {
                            "label": "Delete",
                            "icon" : "/portal/ajax/bills/delete.png",
                            "action": function (data) {
                                var ref = $.jstree.reference(data.reference),
                                    sel = ref.get_selected();
                                if(!sel.length) { return false; }
                                ref.delete_node(sel);
    
                            }
                        }
                    };
                }
            }
        });
    });
 });

 $("#backclicked").click(function(){
    update = 0;
    $("#tmsform").hide();
    $("#tmstable").show();
    $("#name").val("");
    arrayJsTree = JSON.parse("[{ \"text\" : \"PAYMENT\", \"children\" : []}]");
 });

$("#demo-form2" ).submit(function( event ) {
    event.preventDefault();
    $("#btnsend").hide();
    
    var fd = new FormData();

    fd.append('billmenuname', $("#name").val());
    var treeData = $('#jstree_demo_div').jstree(true).get_json('#', {flat:false})
    var jsonData = JSON.stringify(treeData);
    fd.append('menu', jsonData);   
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
        url : "/tms/billing/senddata",
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
    var jsonData = record;
    var cat = id;
    sendId = jsonData[cat].id;
    edit = true;
    gId = record[id].id;
    $("#tmsform").show();
    $("#tmstable").hide();
    update = 2;
    $("#name").val(jsonData[cat].billmenuname);

    $('#jstree_demo_div').jstree("destroy").empty();
    arrayJsTree = JSON.parse(jsonData[cat].menu);
    $(function() {
        $('#jstree_demo_div').jstree(
        {
            "core" : 
            {
                strings : {
                    'New node': 'Category'
                },
                "animation" : 0,
                "check_callback" : true,
                "themes" : 
                { 
                    "stripes" : true 
                },
    
                'data':  arrayJsTree,
            },
            "types" : 
            {
                "#" : 
                {
                    "max_children" : 1,
                    "max_depth" : 1000,
                    "valid_children" : ["root"]
                },
                "root" : 
                {
                    "icon" : "/portal/ajax/bills/treeicon.png",
                    "valid_children" : ["default","category", "biller"]
                },
                "default" : 
                {
                    "valid_children" : ["default","category", "biller"]
                },
                "category" : 
                {
                    "icon" : "/portal/ajax/bills/treeicon.png",
                    "valid_children" : ["default","category", "biller"]
                },
                "biller" : 
                {
                    "icon" : "/portal/ajax/bills/biller.png",
                    "valid_children" : ["default"]
                }
            },
            "plugins" : [
                "contextmenu", "dnd", "search",
                "state", "types", "wholerow"
            ],
            "contextmenu":{
                "items": function () {
                    return {
                        "Create": {
                            "label": "Add Category",
                            "icon" : "/portal/ajax/bills/treeicon.png",
                            "action": function (data) {
                                var inst = $.jstree.reference(data.reference);
                                    obj = inst.get_node(data.reference);
                                if(obj.original.type === 'biller')
                                {
                                    swal(
                                        'Warning',
                                        'You can not add a category in a biller',
                                        'info'
                                    );
                                    return;
                                }else
                                {
                                    var ref = $.jstree.reference(data.reference);
                                        sel = ref.get_selected();
                                    if(!sel.length) { return false; }
                                    sel = sel[0];
                                    sel = ref.create_node(sel, {"type":"category"});
                                    if(sel) {
                                        ref.edit(sel);
                                    }
                                }
                            }
                        },
                        "Biller": {
                            "label": "Add Biller",
                            "icon" : "/portal/ajax/bills/biller.png",
                            "action": function (data) {
                                var inst = $.jstree.reference(data.reference);
                                    obj = inst.get_node(data.reference);
                                if(obj.original.type === 'biller')
                                {
                                    swal(
                                        'Warning',
                                        'You can not add a biller in another biller',
                                        'info'
                                    );
                                    return;
                                }else
                                {
                                    var ref = $.jstree.reference(data.reference);
                                        sel = ref.get_selected();
                                    if(!sel.length) { return false; }
                                    sel = sel[0];
    
                                    var jsonData = bills;
                                    var use = "<div class=\"form-group\">";
                                    use += "<label for=\"cc-ssl\" class=\"control-label mb-1\">All Billers</label>";
                                    use += "<select style=\"color: #001e33; font-weight: bold;\" name=\"cc-ssl\" id=\"listbillers\" class=\"form-control\">";
                                    for(var i = 0; i < jsonData.length; i++) {
                                        //console.log(jsonData[i].billername);
                                        use += "<option style=\"color: #001e33; font-weight: bold;\" value=\"" + jsonData[i].billername + "\">" + jsonData[i].billername + "</option>";
                                    }
                                    use += "</select></div>";
    
                                    var myhtml = document.createElement("div");
                                    myhtml.innerHTML = use;
                                    swal({
                                        title: "Billers",
                                        content: myhtml,
                                        icon: "success",
                                        buttons: {
                                        label: "Add Selected",
                                        remove: "Close"
                                        }
                                    }).then((value) => {
                                        switch (value) {
                                            case "label":
                                                var bilname = $("#listbillers").val();
                                                sel = ref.create_node(sel, {"type":"biller", "text": bilname});
                                                if(sel) {
                                                    ref.edit(sel);
                                                }
                                                break;
                                            case "remove":
                                            default:
                                                break;
                                        }
                                    });
                                }
                            }
                        },
                        "Rename": {
                            "label": "Rename",
                            "icon" : "/portal/ajax/bills/rename.png",
                            "action": function (data) {
                                var inst = $.jstree.reference(data.reference);
                                    obj = inst.get_node(data.reference);
                                inst.edit(obj);
                            }
                        },
                        "Delete": {
                            "label": "Delete",
                            "icon" : "/portal/ajax/bills/delete.png",
                            "action": function (data) {
                                var ref = $.jstree.reference(data.reference),
                                    sel = ref.get_selected();
                                if(!sel.length) { return false; }
                                ref.delete_node(sel);
    
                            }
                        }
                    };
                }
            }
        });
    });
}

function gotoDelete(id)
{
    $.ajax({
        type: "DELETE",
        url : "/tms/billing/billsmenudata/" + record[id].id,
        //data : fd,
        processData: false,
        contentType: false,

        success : function(json) {
            swal(
                'Done!',
                record[id].billmenuname + " deleted.",
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
                record[id].billmenuname + " not deleted.",
                'error'
            );
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
            arr.push(record[i].billmenuname);
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
        url : "/tms/billing/menudata",
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

function getAllBills()
{
    $.ajax({
        type: "GET",
        url : "/tms/billing/getalldata",
        processData: false,
        contentType: false,

        success : function(json) {
            bills = JSON.parse(json.message);
            //console.log(bills)
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
    getAllBills();
    getAllData();
});