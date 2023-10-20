function recover()
{
    var email = $("#email").val();
    if(email === "")
    {
        swal(
            'Error!',
            "No Email Address Provided",
            'error'
        );
        $("#recover_button").text("Recover Password");
        $("#recover_button").removeAttr("disabled");
        return;
    }
    var fd = new FormData();
    fd.append('email', $("#email").val());
    
    $.ajax({
        type: "POST",
        url : "/tms/login/forgetpassword",
        data : fd,
        processData: false,
        contentType: false,

        success : function(json) {
            swal(
                'Success',
                "Your details has been sent to your email address",
                'success'
            );
            $("#recover_button").text("Recover Password");
            $("#recover_button").removeAttr("disabled");
            setTimeout(function() {
                document.location.href="/";
            }, 3000);
        },

        complete: function(){
            $("#recover_button").text("Recover Password");
            $("#recover_button").removeAttr("disabled");
        },
        
        error : function(xhr,errmsg,err) {
            var json = JSON.parse(xhr.responseText);
            swal(
                'Error!',
                json.message,
                'error'
            );
            $("#recover_button").text("Recover Password");
            $("#recover_button").removeAttr("disabled");
        }
    });
}
