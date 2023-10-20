var count = 0;
function login()
{
    var username = $("#username").val();
    var password = $("#password").val();
    if(username === "")
    {
        swal(
            'Error!',
            "No Username Provided",
            'error'
        );
        $("#login_button").text("Log in");
        $("#login_button").removeAttr("disabled");
        return;
    }
    if(password === "")
    {
        swal(
            'Error!',
            "No Password Provided",
            'error'
        );
        $("#login_button").text("Log in");
        $("#login_button").removeAttr("disabled");
        return;
    }
    var fd = new FormData();
    fd.append('username', $("#username").val());
    fd.append('password', $("#password").val());
    fd.append('usertype', "user");
    fd.append('count', count);

    $.ajax({
        type: "POST",
        url : "/tms/login/webverify",
        data : fd,
        processData: false,
        contentType: false,

        success : function(json) {
            if(json.status == 200)
            {
                location.href = "/tms/dashboard/show";
            }else
            {
                location.reload();
            }
        },

        complete: function(){
            $("#login_button").text("Log in");
            $("#login_button").removeAttr("disabled");
        },
        
        error : function(xhr,errmsg,err) {
            var json = JSON.parse(xhr.responseText);
            swal(
                'Error!',
                json.message,
                'error'
            );
            $("#login_button").text("Log in");
            $("#login_button").removeAttr("disabled");
        }
    });
}

$("#signin" ).submit(function( event ) {
    event.preventDefault();
    $("#login_button").text("Logging in...");
    $("#login_button").attr("disabled", "disabled");
    $("#login_button").removeAttr("href");
    login();
    count = count + 1;
});