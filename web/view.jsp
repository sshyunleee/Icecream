<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ page import="java.io.PrintWriter" %>
<%@ page import="bbs.Bbs" %>
<%@ page import="bbs.BbsDAO" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Type" content="text/html"; charset="UTF-8">
<meta name="viewport" content="width=device-width", initial-scale="1">
<link rel="stylesheet" href="css/bootstrap.css">
<link rel="stylesheet" href="css/custom.css">
<title>JSP Website</title>
</head>
<body background="images/bg_menu.jpg">
	<% 
		String userID = null;
		if (session.getAttribute("userID") != null) {
			userID = (String) session.getAttribute("userID");
		}
		int bbsID = 0;
		if (request.getParameter("bbsID") != null) {
			bbsID = Integer.parseInt(request.getParameter("bbsID"));
		}
		if (bbsID == 0) {
			PrintWriter script = response.getWriter();
			script.println("<script>");
			script.println("alert('Not valid.')");
			script.println("location.href = 'bbs.jsp'");
			script.println("history.back()");
			script.println("</script>");
		}
		Bbs bbs = new BbsDAO().getView(bbsID);
		
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
						<th colspan="3" style="background-color: #eeeeee; text-align: center;">QnA view</th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td style="width: 20%;">Title</td>
						<td colspan="2"><%= bbs.getBbsTitle().replaceAll(" ", "&nbsp;").replaceAll("<", "&lt;").replaceAll(">","&gt;").replaceAll("\n", "<br>") %></td>
					</tr>
					<tr>
						<td>Date</td>
						<td colspan="2"><%= bbs.getBbsDate().substring(0, 11) + bbs.getBbsDate().substring(11, 13) + ":" + bbs.getBbsDate().substring(14, 16) %></td>
					</tr>
					<tr>
						<td>Writer</td>
						<td colspan="2"><%= bbs.getUserID() %></td>
					</tr>
					<tr>
						<td>Content</td>
						<td colspan="2" style="min-height: 200px; text-align: left;"><%= bbs.getBbsContent().replaceAll(" ", "&nbsp;")
								.replaceAll("<", "&lt;").replaceAll(">","&gt;").replaceAll("\n", "<br>") %></td>
					</tr>
				</tbody>
			</table>
			<a href="bbs.jsp" class="btn btn-primary">List</a>
			<%
				if (userID != null && userID.equals(bbs.getUserID())) {
			%>
					<a href="update.jsp?bbsID=<%= bbsID %>" class="btn btn-primary">Edit</a>
					<a onclick="return confirm('Delete it?')" href="deleteAction.jsp?bbsID=<%= bbsID %>" class="btn btn-primary">Delete</a>
			<%
				}
			%>		
		</div>
	</div>
	<script src="https://code.jquery.com/jquery-3.1.1.min.js"></script>
	<script src="js/bootstrap.js"></script>
</body>
</html>