var role;
var username;
var tids;
var records;

function checkPlease(value)
{
    for(var i=0; i<tids.length; i++){
        if(tids[i].tid === value){
            return true;
        }
    }
    return false;
}

function gotoView(id)
{
    var use = "<p align=\"left\">";
    use += "CELL STATION INFO: <span style=\"float:right;\">" + records[id].cell_station_information + "</span></br>";
    use += "HAS BATTERY: <span style=\"float:right;\">" + records[id].has_battery + "</span></br>";
    use += "MERCHANT ID: <span style=\"float:right;\">" + records[id].merchant_id + "</span></br>";
    use += "PRINTER STATUS: <span style=\"float:right;\">" + records[id].printer_state + "</span></br>";
    use += "SOFTWARE VERSION: <span style=\"float:right;\">" + records[id].software_version + "</span></br>";
    use += "MANUFACTURER: <span style=\"float:right;\">" + records[id].terminal_manufacturer + "</span></br>";
    use += "MODEL: <span style=\"float:right;\">" + records[id].terminal_model_name + "</span></br>";
    use += "BATTERY LEVEL: <span style=\"float:right;\">" + records[id].battery_level + "</span></br>";
    use += "CHARGE STATUS: <span style=\"float:right;\">" + records[id].charge_status + "</span></br>";
    use += "SERIAL NUMBER: <span style=\"float:right;\">" + records[id].serial_number + "</span></br>";
    use += "DATE: <span style=\"float:right;\">" + records[id].current_date_uzoezi.slice(0, 10) + "</span></br>";
    use += "</p>";
    swal("Transaction Details!", use, "success");
}

$("#exportbutton").click(function(e){
    $("#exportbutton").text("Please Wait");
    $("#exportbutton").prop("disabled",true);
    var table = $('#bootstrap-data-table').DataTable();
    var data = table.rows({filter: 'applied'}).data();
    var exp = [];
    for(var i = 0; i < data.length; i++)
    {
        exp.push(records[i]);
    }
    var myTestXML = new myExcelXML(JSON.stringify(exp));
    myTestXML.downLoad();
    $("#exportbutton").text("Please Reload Page");
    $("#exportbutton").prop("disabled",false);
});


$("#loadOneTidOneWeek").click(function(e){
    if(tids.length < 1)
    {
        swal(
            'Empty!',
            "No Tid Available....",
            'success'
        );
        return;
    }
    $("#loadOneTidOneWeek").text("Please Wait");
    $("#loadOneTidOneWeek").prop("disabled",true);
    swal({
        title: 'Transactions For 7 Days',
        text: "Terminal Id",
		input: 'text',
        type: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#800080',
        cancelButtonColor: '#001e33',
        confirmButtonText: 'Fetch'
    }).then(function (result) {
		if (result.value) 
		{
			$('#loadOneTidOneWeek').html('Loading...');
			$('#loadOneTidOneWeek').prop("disabled", true);
			var table = $('#bootstrap-data-table').DataTable({
					"language": {
						"emptyTable": "Please Wait. Loading..."
					},
					"bDestroy": true
			});
            table.clear().draw();
            
            if(role !== "user")
            {
                var td = result.value;
                if(td.length != 8)
                {
                    swal(
                        'Not Authorized!',
                        "Incorrect Tid.",
                        'error'
                    );
                    $('#loadOneTidOneWeek').html('View Tid Last One Week');
					$('#loadOneTidOneWeek').prop("disabled", false);
                    return;
                }else
                {
                    var j = 0;
                    var i = tids.length - 1;
                    for(; i > -1; i--) {
                        if(tids[i].tid === td)
                        {
                            j = 1;
                            break;
                        }
                    }
                    if(j == 0)
                    {
                        swal(
                            'Not Authorized!',
                            "Incorrect Tid.",
                            'error'
                        );
                        $('#loadOneTidOneWeek').html('View Tid Last One Week');
                        $('#loadOneTidOneWeek').prop("disabled", false);
                        return;
                    }
                }
            }
			$.ajax({
				url: "/tms/state/getOneWeek/" + result.value,
				async: true,
				dataType: 'json',
				success: function (data) {
					records = data;
					var value = "";
                    if(records.length < 1)
					{
						var table = $('#bootstrap-data-table').DataTable({
								"language": {
									"emptyTable": "No Records Found"
								},
								"bDestroy": true
						});
						table.clear().draw();
						$('#loadOneTidOneWeek').html('View Last One Week');
						$('#loadOneTidOneWeek').prop("disabled", false);
						return;
					}
					
					for (var i = 0; i < records.length; i++) 
					{
						arr = [];
                        arr.push(records[i].terminal_id);
                        arr.push(records[i].printer_state);
                        arr.push(records[i].software_version);
                        arr.push(records[i].terminal_manufacturer);
                        arr.push(records[i].terminal_model_name);
                        arr.push(records[i].serial_number);
                        arr.push("<button onclick=\"gotoView('" + i + "');\" type=\"button\" class=\"btn btn-success\">View</button>");
                        if(checkPlease(records[i].terminal_id) === false)
                        {
                            //console.log("Nothing found")
                            continue;
                        }
                        $('#bootstrap-data-table').DataTable().row.add(arr);
					}
					$('#bootstrap-data-table').DataTable().draw();
					$('#loadOneTidOneWeek').html('View Tid Last One Week');
					$('#loadOneTidOneWeek').prop("disabled", false);
				},
				error : function(xhr,errmsg,err) {
					$('#loadOneTidOneWeek').html('Reload Page');
					$('#loadOneTidOneWeek').prop("disabled", false);
					var table = $('#bootstrap-data-table').DataTable({
							"language": {
								"emptyTable": "Please Reload Page."
							},
							"bDestroy": true
					});
					table.clear().draw();
				}
			});
		}else
        {

        }
    });
    $("#loadOneTidOneWeek").text("View Last One Week");
    $("#loadOneTidOneWeek").prop("disabled",false);
});


$("#loadOneTid").click(function(e){
    if(tids.length < 1)
    {
        swal(
            'Empty!',
            "No Tid Available....",
            'success'
        );
        return;
    }
    $("#loadOneTid").text("Please Wait");
    $("#loadOneTid").prop("disabled",true);
    swal({
        title: 'Transactions',
        text: "Terminal Id",
		input: 'text',
        type: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#800080',
        cancelButtonColor: '#001e33',
        confirmButtonText: 'Fetch'
    }).then(function (result) {
		if (result.value) 
		{
			$('#loadOneTid').html('Loading...');
			$('#loadOneTid').prop("disabled", true);
			var table = $('#bootstrap-data-table').DataTable({
					"language": {
						"emptyTable": "Please Wait. Loading..."
					},
					"bDestroy": true
			});
            table.clear().draw();
            if(role !== "user")
            {
                var td = result.value;
                if(td.length != 8)
                {
                    swal(
                        'Not Authorized!',
                        "Incorrect Tid.",
                        'error'
                    );
                    $('#loadOneTidOneWeek').html('View Tid Last One Week');
					$('#loadOneTidOneWeek').prop("disabled", false);
                    return;
                }else
                {
                    var j = 0;
                    var i = tids.length - 1;
                    for(; i > -1; i--) {
                        if(tids[i].tid === td)
                        {
                            j = 1;
                            break;
                        }
                    }
                    if(j == 0)
                    {
                        swal(
                            'Not Authorized!',
                            "Incorrect Tid.",
                            'error'
                        );
                        $('#loadOneTidOneWeek').html('View Tid Last One Week');
                        $('#loadOneTidOneWeek').prop("disabled", false);
                        return;
                    }
                }
            }

			$.ajax({
				url: "/tms/state/getTidToday/" + result.value,
				async: true,
				dataType: 'json',
				success: function (data) {
					records = data;
					if(records.length < 1)
					{
						var table = $('#bootstrap-data-table').DataTable({
								"language": {
									"emptyTable": "No Records Found"
								},
								"bDestroy": true
						});
						table.clear().draw();
						$('#loadOneTid').html('View Tid Today');
						$('#loadOneTid').prop("disabled", false);
						return;
					}
					for (var i = 0; i < records.length; i++) 
					{
						arr = [];
                        arr.push(records[i].terminal_id);
                        arr.push(records[i].printer_state);
                        arr.push(records[i].software_version);
                        arr.push(records[i].terminal_manufacturer);
                        arr.push(records[i].terminal_model_name);
                        arr.push(records[i].serial_number);
                        arr.push("<button onclick=\"gotoView('" + i + "');\" type=\"button\" class=\"btn btn-success\">View</button>");
                        if(checkPlease(records[i].terminal_id) === false)
                        {
                            //console.log("Nothing found")
                            continue;
                        }
                        $('#bootstrap-data-table').DataTable().row.add(arr);
					}
					$('#bootstrap-data-table').DataTable().draw();
					$('#loadOneTid').html('View Tid Today');
					$('#loadOneTid').prop("disabled", false);
				},
				error : function(xhr,errmsg,err) {
					$('#loadOneTid').html('Reload Page');
					$('#loadOneTid').prop("disabled", false);
					var table = $('#bootstrap-data-table').DataTable({
							"language": {
								"emptyTable": "Please Reload Page."
							},
							"bDestroy": true
					});
					table.clear().draw();
				}
			});
		}else
        {

        }
    });
    $("#loadOneTid").text("View Tid Today");
    $("#loadOneTid").prop("disabled",false);
});

$("#loadallTids").click(function(e){
    if(tids.length < 1)
    {
        swal(
            'Empty!',
            "No Tid Available....",
            'success'
        );
        return;
    }
    $("#loadallTids").text("Please Wait");
    $("#loadallTids").prop("disabled",true);
	var table = $('#bootstrap-data-table').DataTable({
			"language": {
				"emptyTable": "Please Wait. Loading..."
			},
			"bDestroy": true
	});
	table.clear().draw();
	$.ajax({
		url: "/tms/state/getAllToday",
		async: true,
		dataType: 'json',
		success: function (data) {
			records = data;
			if(records.length < 1)
			{
				var table = $('#bootstrap-data-table').DataTable({
						"language": {
							"emptyTable": "No Records Found"
						},
						"bDestroy": true
				});
				table.clear().draw();
				$('#loadallTids').html("Today's Transactions");
				$('#loadallTids').prop("disabled", false);
				return;
			}
			for (var i = 0; i < records.length; i++) 
			{
                arr = [];
				arr.push(records[i].terminal_id);
				arr.push(records[i].printer_state);
                arr.push(records[i].software_version);
                arr.push(records[i].terminal_manufacturer);
                arr.push(records[i].terminal_model_name);
                arr.push(records[i].serial_number);
				arr.push("<button onclick=\"gotoView('" + i + "');\" type=\"button\" class=\"btn btn-success\">View</button>");
                if(checkPlease(records[i].terminal_id) === false)
                {
                    //console.log("Nothing found")
                    continue;
                }
                $('#bootstrap-data-table').DataTable().row.add(arr);
			}
			$('#bootstrap-data-table').DataTable().draw();
			$('#loadallTids').html("Today's Transactions");
			$('#loadallTids').prop("disabled", false);
		},
		error : function(xhr,errmsg,err) {
			$('#loadallTids').html('Reload Page');
			$('#loadallTids').prop("disabled", false);
			var table = $('#bootstrap-data-table').DataTable({
					"language": {
						"emptyTable": "Please Reload Page."
					},
					"bDestroy": true
			});
			table.clear().draw();
        }
	});
    $("#loadallTids").text("Today's Transactions");
    $("#loadallTids").prop("disabled",false);
});


function getAllTerminals()
{
    $.ajax({
        type: "GET",
        url : "/tms/state/getalltids",
        processData: false,
        contentType: false,

        success : function(json) {
            tids = JSON.parse(json.message);
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
    role = details.role;
    username = details.username;
    getAllTerminals();
});