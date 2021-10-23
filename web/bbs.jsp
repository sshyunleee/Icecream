<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ page import="java.io.PrintWriter" %>
<%@ page import="bbs.BbsDAO" %>
<%@ page import="bbs.Bbs" %>
<%@ page import="java.util.ArrayList" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Type" content="text/html"; charset="UTF-8">
<meta name="viewport" content="width=device-width", initial-scale="1">
<link rel="stylesheet" href="css/bootstrap.css">
<link rel="stylesheet" href="css/custom.css">
<title>JSP Website</title>
<style type="text/css">
	a, a:hover {
		color: #000000;
		text-decoration: none;
	}
</style>
</head>
<body background="images/bg_menu.jpg">
	<% 
		String userID = null;
		if (session.getAttribute("userID") != null) {
			userID = (String) session.getAttribute("userID");
		}
		int pageNumber = 1;
		if (request.getParameter("pageNumber") != null) {
			pageNumber = Integer.parseInt(request.getParameter("pageNumber"));
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
	<div class="container">
		<div class="row">
			<table class="table table-striped" style="text-align: center; border: 1px solid #dddddd">
				<thead>
					<tr>
						<th style="background-color: #eeeeee; text-align: center;">No.</th>
						<th style="background-color: #eeeeee; text-align: center;">Title</th>
						<th style="background-color: #eeeeee; text-align: center;">Date</th>
						<th style="background-color: #eeeeee; text-align: center;">Writer</th>
					</tr>
				</thead>
				<tbody>				
					<%
						BbsDAO bbsDAO = new BbsDAO();
						ArrayList<Bbs> list = bbsDAO.getBbsList(pageNumber);
						for (int i = 0; i < list.size(); i++) {
					%>
					<tr>
						<td><%= list.get(i).getBbsID() %></td>
						<td><a href="view.jsp?bbsID=<%= list.get(i).getBbsID() %>"><%= list.get(i).getBbsTitle()
								.replaceAll(" ", "&nbsp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll("\n", "<br>") %></a></td>
						<td><%= list.get(i).getBbsDate().substring(0, 11) + list.get(i).getBbsDate().substring(11, 13) + ":" + list.get(i).getBbsDate().substring(14, 16) %></td>
						<td><%= list.get(i).getUserID() %></td>
					</tr>
					<%		
						}
					%>
				</tbody>
			</table>
			<% 
				if (pageNumber != 1) {
			%>
				<a href="bbs.jsp?pageNumber=<%=pageNumber - 1%>" class="btn btn-success btn-arrow-left">Previous</a>
			<%
				} if (bbsDAO.paging(pageNumber + 1)) {
			%>
				<a href="bbs.jsp?pageNumber=<%=pageNumber + 1%>" class="btn btn-success btn-arrow-left">Next</a>
			<%
				}
			%>
			<a href="write.jsp" class="btn btn-primary pull-right">Write</a>
		</div>
	</div>
	<script src="https://code.jquery.com/jquery-3.1.1.min.js"></script>
	<script src="js/bootstrap.js"></script>
</body>
</html>