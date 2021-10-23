package user;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;


public class UserDAO {
	
	private Connection conn;
	private PreparedStatement pstmt;
	private ResultSet rs;
	
	public UserDAO() {
		try {
			String dbURL = "jdbc:mysql://localhost:3306/BBS";
			String dbID = "root";
			String dbPassword = "";
			Class.forName("com.mysql.cj.jdbc.Driver");
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
				return -1; // Wrong ID
			} else {
				int checkLock = rs.getInt(4);
				Boolean check = (checkLock == 1);
				if(check){
					return 5;
				}
				// Password hash
				String Salt = rs.getString(2);
				String Password = userPassword;
				MessageDigest md = MessageDigest.getInstance("SHA-512");
				// key-stretching
				for(int i = 0; i < 1000; i++) {
					// Add salt
					String temp = Password + Salt;
					md.update(temp.getBytes());
					// Get digest
					Password = BtS(md.digest());
				}
				if (rs.getString(1).equals(Password)) {
					// loginFail -> 0
					String fail = "UPDATE USER SET loginFail = 0 WHERE userID = ?";
					pstmt = conn.prepareStatement(fail);
					pstmt.setString(1,  userID);
					pstmt.executeUpdate();
					// Success
					return 1;
				} else {
					if(rs.getInt(3) == 4){
						// loginFail -> 0, isLock -> 1
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
					// Wrong Password
					return 0;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		// DB Error
		return -2;
	}

	// Byte to String
	private String BtS(byte[] temp) {
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
		String Salt = BtS(salt);
		String Password = user.getUserPassword();
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		// key-stretching
		for(int i = 0; i < 1000; i++) {
			String temp = Password + Salt;
			md.update(temp.getBytes());
			Password = BtS(md.digest());
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
		// DB Error
		return -1;
	}
}
