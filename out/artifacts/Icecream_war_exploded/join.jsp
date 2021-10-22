<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html"; charset="UTF-8">
<meta name="viewport" content="width=device-width", initial-scale="1">
<link rel="stylesheet" href="css/bootstrap.css">
<link rel="stylesheet" href="css/custom.css">
<title>JSP Website</title>
</head>
<body background="images/bg_menu.jpg">
	<div class="row center-block">
		<a class="center-block" href="home.jsp" style="margin: 20px 0 20px 0">
			<img src="images/baskin-logo.png" height="60">
		</a>
	</div>
	<nav class="navbar-default">
		<div class="collapse navbar-collapse" id="bs-example-navbar-collapse-1">
			<ul class="nav navbar-nav navbar-left">
				<li><a style="color: palevioletred" href="login.jsp" ><b>LOGIN</b></a></li>
				<li><a href="join.jsp"><b>JOIN</b></a></li>
			</ul>
			<ul class="nav navbar-nav navbar-right">
				<li class="active"><a href="home.jsp"><b>HOME</b></a></li>
				<li><a href="bbs.jsp"><b>Q&A</b></a></li>
				<li><a href="#" onclick="nav_btn()"><b>MENU</b></a></li>
				<li><a href="#" onclick="nav_btn()"><b>EVENT</b></a></li>
				<li><a href="#" onclick="nav_btn()"><b>STORE</b></a></li>
				<li><a href="#" onclick="nav_btn()"><b>ABOUT &nbsp; </b></a></li>
			</ul>
		</div>
	</nav>
	<div class="container">
		<div class="col-lg-4"></div>
		<div class="col-lg-4">
			<div class="jumbotron" style="padding-top: 20px;">
				<form method="post" action="joinAction.jsp">
					<h3 style="text-align: center;">Join form</h3>
					<div class="form-group">
						<input type="text" class="form-control" placeholder="ID" name="userID" maxlength="20">
					</div>
					<div class="form-group">
						<input type="password" class="form-control" placeholder="Password" name="userPassword" maxlength="20">
					</div>
					<div class="form-group">
						<input type="text" class="form-control" placeholder="Name" name="userName" maxlength="20">
					</div>
					<div class="form-group" style="text-align: center;">
						<div class="btn-group" data-toggle="buttons">
							<label class="btn btn-primary active">
								<input type="radio" name="userGender" autocomplete="off" value="남자" checked>Male
							</label>
						</div>
						<div class="btn-group" data-toggle="buttons">
							<label class="btn btn-primary">
								<input type="radio" name="userGender" autocomplete="off" value="여자" checked>Female
							</label>
						</div>
					</div>
					<div class="form-group">
						<input type="email" class="form-control" placeholder="Email" name="userEmail" maxlength="20">
					</div>
					<input type="submit" class="btn btn-primary form-control" value="Join">
				</form>
			</div>
		</div>
		<div class="col-lg-4"></div>
	</div>
	<script src="https://code.jquery.com/jquery-3.1.1.min.js"></script>
	<script src="js/bootstrap.js"></script>
</body>
</html>