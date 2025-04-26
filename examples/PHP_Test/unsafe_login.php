<?php

$host = 'localhost';
$db = 'unsafe_db';
$user = 'root';
$pass = '';

$conn = new mysqli($host, $user, $pass, $db);

if ($conn->connect_error) {
    die("connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];

    //SQL Query is vulnerable to SQL injection, Stored XSS, CSRF, and database dumping.
    $query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
    $result = $conn->query($query);

    if ($result->num_rows > 0) {
        echo "login successful.<br>";
    } else {
        echo "invalid username or password.<br>";
    }
}

$conn->close();
?>