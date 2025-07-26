// Test file with various Java vulnerabilities for the scanner

import java.sql.*;
import java.security.MessageDigest;
import java.io.*;
import java.util.Scanner;
import javax.servlet.http.*;

public class VulnerableJavaApp {
    
    // OWASP A02: Cryptographic Failures
    private static final String PASSWORD = "admin123"; // Hardcoded password
    private static final String API_KEY = "sk-1234567890abcdef"; // Hardcoded API key
    private static final String SECRET = "my-secret-key"; // Hardcoded secret
    
    // SANS CWE-327: Weak Cryptography
    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5"); // Weak MD5 hashing
        byte[] hash = md.digest(password.getBytes());
        return new String(hash);
    }
    
    public String weakSHA1Hash(String data) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA1"); // Weak SHA-1
        return new String(sha1.digest(data.getBytes()));
    }
    
    // OWASP A03 & SANS CWE-89: SQL Injection
    public ResultSet getUserData(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE id = " + userId; // SQL Injection
        return stmt.executeQuery(query);
    }
    
    public void updateUser(String name, String email) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        String sql = "UPDATE users SET email = '" + email + "' WHERE name = '" + name + "'"; // SQL Injection
        Statement stmt = conn.createStatement();
        stmt.execute(sql);
    }
    
    // SANS CWE-78: OS Command Injection
    public void executeCommand(String userInput) throws IOException {
        Runtime.getRuntime().exec("ping " + userInput); // Command injection
    }
    
    public void systemCall(String filename) throws IOException {
        Process p = Runtime.getRuntime().exec("cat " + filename); // Command injection
    }
    
    // SANS CWE-120: Buffer Overflow (simulated in Java context)
    public void unsafeStringOperation(String input) {
        char[] buffer = new char[10];
        // Potential buffer overflow if input length > 10
        input.getChars(0, input.length(), buffer, 0);
    }
    
    // SANS CWE-22: Path Traversal
    public String readFile(String filename) throws IOException {
        FileInputStream fis = new FileInputStream(filename); // No path validation
        Scanner scanner = new Scanner(fis);
        return scanner.nextLine();
    }
    
    public void writeFile(String filename, String content) throws IOException {
        FileWriter writer = new FileWriter(filename); // Path traversal vulnerability
        writer.write(content);
        writer.close();
    }
    
    // OWASP A07: Authentication Failures
    public boolean authenticate(String username, String password) {
        if (password.equals("password123")) { // Weak password check
            return true;
        }
        return false;
    }
    
    public boolean isAdmin(HttpServletRequest request) {
        String user = request.getParameter("user");
        if (user != null) { // Insufficient authorization check
            return true;
        }
        return false;
    }
    
    // SANS CWE-79: Cross-site Scripting
    public void displayMessage(HttpServletResponse response, String message) throws IOException {
        PrintWriter out = response.getWriter();
        out.println("<div>" + message + "</div>"); // XSS vulnerability - no encoding
    }
    
    // SANS CWE-352: CSRF
    public void updateProfile(HttpServletRequest request) {
        // Missing CSRF token validation
        String name = request.getParameter("name");
        String email = request.getParameter("email");
        // Update user profile without CSRF protection
    }
    
    // SANS CWE-434: Unrestricted Upload
    public void uploadFile(HttpServletRequest request) throws Exception {
        // No file type validation
        String filename = request.getParameter("filename");
        FileOutputStream fos = new FileOutputStream("/uploads/" + filename);
        // File upload without validation
    }
    
    // SANS CWE-285: Improper Authorization
    public void adminFunction(HttpServletRequest request) {
        String sessionId = request.getParameter("sessionId");
        if (sessionId != null) { // Weak authorization
            // Perform admin operations
        }
    }
    
    // SANS CWE-732: Incorrect Permission Assignment
    public void createFile(String filename) throws IOException {
        File file = new File(filename);
        file.createNewFile();
        file.setReadable(true, false); // World-readable
        file.setWritable(true, false); // World-writable
    }
    
    // SANS CWE-209: Information Exposure
    public void handleError(Exception e, HttpServletResponse response) throws IOException {
        PrintWriter out = response.getWriter();
        out.println("Error: " + e.getMessage()); // Exposing error details
        e.printStackTrace(); // Stack trace exposure
    }
    
    // SANS CWE-190: Integer Overflow
    public int calculateSize(String input) {
        int size = Integer.parseInt(input); // No bounds checking
        return size * 1024; // Potential overflow
    }
    
    // SANS CWE-476: NULL Pointer Dereference
    public String processUser(String user) {
        return user.toUpperCase(); // No null check
    }
    
    // SANS CWE-94: Code Injection
    public void executeScript(String script) throws Exception {
        // Dangerous: executing user-provided script
        javax.script.ScriptEngineManager manager = new javax.script.ScriptEngineManager();
        javax.script.ScriptEngine engine = manager.getEngineByName("JavaScript");
        engine.eval(script); // Code injection
    }
    
    // SANS CWE-502: Deserialization
    public Object deserializeObject(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject(); // Unsafe deserialization
    }
    
    // SANS CWE-918: SSRF
    public String fetchUrl(String url) throws IOException {
        java.net.URL targetUrl = new java.net.URL(url); // No URL validation
        java.net.URLConnection conn = targetUrl.openConnection();
        Scanner scanner = new Scanner(conn.getInputStream());
        return scanner.nextLine();
    }
    
    // SANS CWE-125: Out-of-bounds Read
    public char getCharAt(String input, int index) {
        return input.charAt(index); // No bounds checking
    }
    
    // SANS CWE-20: Improper Input Validation
    public void processInput(String input) {
        // No input validation
        System.out.println("Processing: " + input);
        // Direct use without sanitization
    }
    
    // Additional vulnerabilities
    public void logSensitiveData(String password, String token) {
        System.out.println("Password: " + password); // Logging sensitive data
        System.out.println("Token: " + token);
    }
    
    // OWASP A05: Security Misconfiguration
    public static final boolean DEBUG_MODE = true; // Debug enabled in production
    
    // Weak random number generation
    public int generateRandomNumber() {
        return (int) (Math.random() * 1000); // Weak randomness
    }
}