

$(function() {
	var myAlert = $("#alert");

	mybg = document.createElement("div");
	mybg.setAttribute("id","mybg");
	mybg.style.background = "#000";
	mybg.style.width = "100%";
	mybg.style.height = "100%";
	mybg.style.position = "fixed";
	mybg.style.top = "0";
	mybg.style.left = "0";
	mybg.style.zIndex = "400";
	mybg.style.opacity = "0.3";
	mybg.style.filter = "Alpha(opacity=30)";
	mybg.style.display = "none";

	document.body.appendChild(mybg);

	$('#mybg').click(function(e) {
		if (myAlert.css("display") === "block") {
			myAlert.css("display", "none");
			$('#register-form-link').removeClass('active');
			$('#login-form-link').removeClass('active');
			$(this).css("display", "none");
			$("body").css('overflow', 'visible');
		}
	});
	var top = "30%";
	var left = "30%";
	$('#signin-pop').click(function(e) {
		myAlert.css("top",top);
		myAlert.css("left",left);
		$('#register-form-link').removeClass('active');
		$('#login-form-link').addClass('active');
		$('#login-form').css("display", "block");
		$('#register-form').css("display", "none");
		myAlert.css("display", "block");
		mybg.style.display = "block";
		$("body").css("overflow", "hidden");




	});

	$('#signup-pop').click(function(e) {
		myAlert.css("top",top);
		myAlert.css("left", left);
		$('#login-form-link').removeClass('active');
		$('#register-form-link').addClass('active');
		$('#login-form').css("display", "none");
		$('#register-form').css("display", "block");
		myAlert.css("display", "block");

		mybg.style.display = "block";

		$("body").css("overflow", "hidden");




	});

    $('#login-form-link').click(function(e) {
		$("#login-form").delay(100).fadeIn(100);
 		$("#register-form").fadeOut(100);
		$('#register-form-link').removeClass('active');
		$(this).addClass('active');
		e.preventDefault();
	});
	$('#register-form-link').click(function(e) {
		$("#register-form").delay(100).fadeIn(100);
 		$("#login-form").fadeOut(100);
		$('#login-form-link').removeClass('active');
		$(this).addClass('active');
		e.preventDefault();
	});

	$('#confirmDelete').click(function(e) {
		var msg = "Are you sure you want to delete this post?";
		if (confirm(msg)) {
			$("#deletePost").submit();
		}
	});

});
