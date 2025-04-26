<?php

$host = 'localhost';
$db = 'unsafe_db';
$user = 'root';
$pass = '';

$conn = new mysqli($host, $user, $pass, $db);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password']; // Password is taken as plain text

    ////SQL Query is vulnerable to SQL injection, Stored XSS, CSRF, and database dumping.
    $query = "INSERT INTO users (username, password) VALUES ('$username', '$password')";
    if ($conn->query($query) === TRUE) {
        header("Location: confirmation.php");
        exit();
    } else {
        header("Location: index.html?msg=Error: " . urlencode($conn->error));
        exit();
    }
}

$conn->close();
?>