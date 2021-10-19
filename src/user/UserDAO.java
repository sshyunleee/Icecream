package user;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static java.lang.System.out;


public class UserDAO {
	
	private Connection conn;
	private PreparedStatement pstmt;
	private ResultSet rs;
	
	public UserDAO() {
		try {
			String dbURL = "jdbc:mysql://localhost:3306/BBS?";
			String dbID = "root";
			String dbPassword = "";
			Class.forName("com.mysql.jdbc.Driver");
			conn = DriverManager.getConnection(dbURL, dbID, dbPassword);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public int login(String userID, String userPassword) {
		String SQL = "SELECT userPassword, userSalt, loginFail, isLock FROM USER WHERE userID = ?";
		try {
			pstmt = conn.prepareStatement(SQL);
			pstmt.setString(1,  userID);
			rs = pstmt.executeQuery();
			Boolean checkID = rs.next();
			if (checkID == false) {
				return -1; // 아이디가 없음
			} else {
				int checkLock = rs.getInt(4);
				Boolean check = (checkLock == 1);
				if(check){
					return 5;
				}
				String Salt = rs.getString(2);
				String Password = userPassword;
				// 비밀번호 해싱
				MessageDigest md = MessageDigest.getInstance("SHA-256");// SHA-256 해시함수를 사용
				// key-stretching
				for(int i = 0; i < 1000; i++) {
					String temp = Password + Salt;			// 패스워드와 Salt 를 합쳐 새로운 문자열 생성
					md.update(temp.getBytes());				// temp 의 문자열을 해싱하여 md 에 저장해둔다
					Password = Byte_to_String(md.digest());	// md 객체의 다이제스트를 얻어 password 를 갱신한다
				}
				if (rs.getString(1).equals(Password)) {
					// loginFail 0으로 수정
					String fail = "UPDATE USER SET loginFail = 0 WHERE userID = ?";
					pstmt = conn.prepareStatement(fail);
					pstmt.setString(1,  userID);
					pstmt.executeUpdate();
					return 1; // 로그인 성공
				} else {
					if(rs.getInt(3) == 4){
						// loginFail 0으로 수정, isLock Y로 수정
						String fail = "UPDATE USER SET loginFail = 0 WHERE userID = ?";
						pstmt = conn.prepareStatement(fail);
						pstmt.setString(1,  userID);
						pstmt.executeUpdate();
						String lock = "UPDATE USER SET isLock = 1 WHERE userID = ?";
						pstmt = conn.prepareStatement(lock);
						pstmt.setString(1,  userID);
						pstmt.executeUpdate();
					} else {
						// loginFail++
						int count = rs.getInt(3)+1;
						String fail = "UPDATE USER SET loginFail = ? WHERE userID = ?";
						pstmt = conn.prepareStatement(fail);
						pstmt.setInt(1,  count);
						pstmt.setString(2,  userID);
						pstmt.executeUpdate();
					}
					return 0; // 비밀번호 불일치
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		} 
		return -2; // 데이터베이스 오류
	}

	// 바이트 값을 16진수로 변경해준다
	private String Byte_to_String(byte[] temp) {
		StringBuilder sb = new StringBuilder();
		for(byte a : temp) {
			sb.append(String.format("%02x", a));
		}
		return sb.toString();
	}

	public int join(User user) throws Exception {
		String SQL = "INSERT INTO USER (userID, userPassword, userName, userGender, userEmail, userSalt) VALUES (?, ?, ?, ?, ?, ?)";
		SecureRandom rnd = new SecureRandom();
		byte[] salt = new byte[20];
		rnd.nextBytes(salt);
		String Salt = Byte_to_String(salt);
		String Password = user.getUserPassword();
		// 비밀번호 해싱
		MessageDigest md = MessageDigest.getInstance("SHA-256");// SHA-256 해시함수를 사용
		// key-stretching
		for(int i = 0; i < 1000; i++) {
			String temp = Password + Salt;	// 패스워드와 Salt 를 합쳐 새로운 문자열 생성
			md.update(temp.getBytes());						// temp 의 문자열을 해싱하여 md 에 저장해둔다
			Password = Byte_to_String(md.digest());			// md 객체의 다이제스트를 얻어 password 를 갱신한다
		}

		try {
			pstmt = conn.prepareStatement(SQL);
			pstmt.setString(1, user.getUserID());
			pstmt.setString(2, Password);
			pstmt.setString(3, user.getUserName());
			pstmt.setString(4, user.getUserGender());
			pstmt.setString(5, user.getUserEmail());
			pstmt.setString(6, Salt);

			return pstmt.executeUpdate();
		} catch(Exception e) {
			e.printStackTrace();
		}
		return -1;
	}

}
