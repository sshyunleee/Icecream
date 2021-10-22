<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ page import="java.io.PrintWriter" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Type" content="text/html"; charset="UTF-8">
<meta name="viewport" content="width=device-width", initial-scale="1">
<link rel="stylesheet" href="css/bootstrap.css">
<link rel="stylesheet" href="css/custom.css">
<title>JSP Website</title>
	<style>
		img {
			display: block;
			margin: auto;
		}

		div.gallery {
			margin: 5px;
			border: 1px solid #ccc;
			float: left;
		}

		div.gallery:hover {
			border: 1px solid #777;
		}

		div.gallery img {
			width: 100%;
			height: auto;
		}

		div.desc {
			padding: 15px;
			text-align: center;
		}
	</style>
	<script>
		function nav_btn(){ alert("Developing now."); }
	</script>
</head>
<body background="images/bg_menu.jpg">
	<% 
		String userID = null;
		if (session.getAttribute("userID") != null) {
			userID = (String) session.getAttribute("userID");
		}
	%>
	<div class="row center-block">
		<a class="center-block" href="home.jsp" style="margin: 20px 0 20px 0">
			<img src="images/baskin-logo.png" height="60">
		</a>
	</div>
	<nav class="navbar-default">
		<div class="collapse navbar-collapse" id="bs-example-navbar-collapse-1">
			<%
				if (userID == null) {
			%>
			<ul class="nav navbar-nav navbar-left">
				<li><a style="color: palevioletred" href="login.jsp" ><b>LOGIN</b></a></li>
				<li><a href="join.jsp"><b>JOIN</b></a></li>
			</ul>
			<%
			} else {
			%>
			<ul class="nav navbar-nav navbar-left">
				<li><a href="logoutAction.jsp"><b>LOGOUT</b></a></li>
			</ul>
			<%
				}
			%>
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

	<img src="images/baskin-banner.png" width="100%" style="margin-bottom: 5px">
	<div id="myCarousel" class="carousel slide" data-ride= "carousel">
		<ol class="carousel-indicators">
			<li data-target="#myCarousel" data-slide-to="0" class="active"></li>
			<li data-target="#myCarousel" data-slide-to="1"></li>
			<li data-target="#myCarousel" data-slide-to="2"></li>
		</ol>
		<div class="carousel-inner">
			<div class="item active">
				<img src="images/bskin-photo-1.jpg">
			</div>
			<div class="item">
				<img src="images/bskin-photo-2.jpg">
			</div>
			<div class="item">
				<img src="images/bskin-photo-3.jpg">
			</div>
		</div>
		<a class="left carousel-control" data-slide="prev" href="#myCarousel"><img src="images/left.png" width="80" style="margin-top: 400px"></a>
		<a class="right carousel-control" data-slide="next" href="#myCarousel"><img src="images/right.png" width="80" style="margin-top: 400px"></a>
	</div>
	<div class="gallery">
		<a target="_blank" href="">
			<img src="images/icecream-1.png" alt="" height="400">
		</a>
		<div class="desc">치즈 고구마구마</div>
	</div>
	<div class="gallery">
		<a target="_blank" href="">
			<img src="images/icecream-2.png" alt="" height="400">
		</a>
		<div class="desc">블랙 할로윈</div>
	</div>
	<div class="gallery">
		<a target="_blank" href="">
			<img src="images/icecream-3.png" alt="" height="400">
		</a>
		<div class="desc">찰떡콩떡</div>
	</div>
	<div class="gallery">
		<a target="_blank" href="">
			<img src="images/icecream-4.png" alt="" height="400">
		</a>
		<div class="desc">허쉬 쿠키&모찌</div>
	</div>
	<div class="gallery">
		<a target="_blank" href="">
			<img src="images/icecream-5.png" alt="" height="400">
		</a>
		<div class="desc">체다치즈 앤 포테이토</div>
	</div>
	<div class="gallery">
		<a target="_blank" href="">
			<img src="images/icecream-6.png" alt="" height="400">
		</a>
		<div class="desc">우낀소(우유속에 끼인 소보로)</div>
	</div>
	<div class="gallery">
		<a target="_blank" href="">
			<img src="images/icecream-7.png" alt="" height="400">
		</a>
		<div class="desc">오레오 쿠키 앤 크림</div>
	</div>
	<div class="gallery">
		<a target="_blank" href="">
			<img src="images/icecream-8.png" alt="" height="400">
		</a>
		<div class="desc">월넛</div>
	</div>
	<div class="gallery">
		<a target="_blank" href="">
			<img src="images/icecream-9.png" alt="" height="400">
		</a>
		<div class="desc">오레오 쿠키 앤 밀크</div>
	</div>
	<div class="gallery">
		<a target="_blank" href="">
			<img src="images/icecream-10.png" alt=""  height="400">
		</a>
		<div class="desc">파핑파핑 바나나</div>
	</div>
	<div class="gallery">
		<a target="_blank" href="">
			<img src="images/icecream-11.png" alt="" height="400">
		</a>
		<div class="desc">에스프레소 앤 크림</div>
	</div>
	<div class="gallery">
		<a target="_blank" href="">
			<img src="images/icecream-12.png" alt="" height="400">
		</a>
		<div class="desc">초코 아몬드 봉봉</div>
	</div>
	<script src="https://code.jquery.com/jquery-3.1.1.min.js"></script>
	<script src="js/bootstrap.js"></script>
</body>
</html>