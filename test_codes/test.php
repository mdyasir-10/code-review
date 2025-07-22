<?php
/*
Vulnerable PHP code for testing security scanner
WARNING: This code contains intentional vulnerabilities for testing purposes only
*/

// Hardcoded credentials
$db_password = "root123";
$api_key = "sk-abcdef1234567890";
$secret_token = "jwt_secret_key_123";

// SQL Injection vulnerabilities
function authenticate_user($username, $password) {
    $connection = mysqli_connect("localhost", "root", $db_password, "testdb");
    
    // Vulnerable: Direct concatenation in SQL query
    $query = "SELECT * FROM users WHERE username = '" . $_POST['username'] . "' AND password = '" . $_POST['password'] . "'";
    $result = mysqli_query($connection, $query);
    
    // Another SQL injection pattern
    $sql = "SELECT id FROM accounts WHERE email = " . $_GET['email'];
    mysqli_query($connection, $sql);
    
    return $result;
}

function search_products($category) {
    global $db_password;
    $conn = new mysqli("localhost", "user", $db_password, "shop");
    
    // Multiple SQL injection vulnerabilities
    $query = "SELECT * FROM products WHERE category = '" . $_REQUEST['cat'] . "'";
    $result = $conn->query($query);
    
    $update_sql = "UPDATE stats SET views = views + 1 WHERE product_id = " . $_COOKIE['last_viewed'];
    $conn->query($update_sql);
    
    return $result;
}

// XSS (Cross-Site Scripting) vulnerabilities
function display_user_profile($user_id) {
    // Vulnerable: Direct output of user input
    echo "Welcome back, " . $_GET['name'];
    
    // Another XSS pattern
    print "Your message: " . $_POST['message'];
    
    // Printf with user input
    printf("Hello %s, your role is %s", $_GET['username'], $_SESSION['role']);
}

function show_search_results() {
    // Multiple XSS vulnerabilities
    echo "<h1>Search Results for: " . $_GET['q'] . "</h1>";
    print "<p>Found " . $_REQUEST['count'] . " results</p>";
    printf("<div>Query: %s</div>", $_POST['search_term']);
}

// Command Injection vulnerabilities
function backup_file($filename) {
    // Vulnerable: Direct execution with user input
    $command = "cp " . $_GET['file'] . " /backup/";
    exec($command);
    
    // Another command injection pattern
    system("tar -czf backup.tar.gz " . $_POST['directory']);
    
    // Shell execution with user input
    shell_exec("find /uploads -name " . $_REQUEST['pattern']);
}

function process_image($image_path) {
    // Multiple command injection vulnerabilities
    passthru("convert " . $_FILES['image']['name'] . " -resize 100x100 thumbnail.jpg");
    popen("identify " . $_GET['img_path'], "r");
    
    return true;
}

// File Inclusion vulnerabilities
function load_page($page) {
    // Vulnerable: Direct file inclusion
    include $_GET['page'] . ".php";
    
    // Another file inclusion pattern
    require_once $_POST['template'] . ".inc";
    
    // Include with REQUEST
    include_once $_REQUEST['module'] . "/config.php";
}

function load_language($lang) {
    // More file inclusion vulnerabilities
    require "lang/" . $_COOKIE['language'] . ".php";
    include_once $_SERVER['HTTP_X_LANGUAGE'] . "/strings.php";
}

// Code Injection vulnerabilities
function calculate_expression($formula) {
    // Extremely dangerous: eval with user input
    $result = eval("return " . $_POST['expression'] . ";");
    
    // Another eval pattern
    eval("\$value = " . $_GET['calc'] . ";");
    
    return $result;
}

// Mixed vulnerabilities in one function
function process_user_data() {
    global $secret_token;
    
    // SQL injection
    $query = "INSERT INTO logs VALUES ('" . $_POST['data'] . "', '" . $secret_token . "')";
    mysql_query($query);
    
    // XSS
    echo "Processing: " . $_GET['input'];
    
    // Command injection
    exec("echo " . $_REQUEST['log_entry'] . " >> /var/log/app.log");
    
    // File inclusion
    include $_POST['config_file'] . ".conf";
    
    // Code injection
    eval("process_" . $_GET['action'] . "();");
}

// Configuration with more hardcoded secrets
define('DB_PASSWORD', 'secretpass123');
define('JWT_SECRET', 'my-jwt-secret-key-456');
$config = array(
    'mysql_password' => 'dbpass789',
    'encryption_key' => 'aes-key-abcdef123456',
    'oauth_secret' => 'oauth-secret-987654321'
);

// Main execution
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    authenticate_user($_POST['user'], $_POST['pass']);
    display_user_profile($_POST['id']);
    backup_file($_POST['filename']);
    load_page($_POST['page']);
    calculate_expression($_POST['expr']);
}

?>