<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['Login'])) {
    // Database connection
    $conn = new mysqli('localhost', 'username', 'password', 'database');
    
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // Get and sanitize input
    $user = $_POST['username'];
    $pass = $_POST['password'];

    // Prepare statement
    $stmt = $conn->prepare("SELECT * FROM users WHERE user = ?");
    $stmt->bind_param("s", $user);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result && $result->num_rows === 1) {
        $row = $result->fetch_assoc();

        // Verify password (assuming password is hashed with password_hash())
        if (password_verify($pass, $row['password'])) {
            $avatar = htmlspecialchars($row["avatar"], ENT_QUOTES, 'UTF-8');
            $userSafe = htmlspecialchars($user, ENT_QUOTES, 'UTF-8');
            echo "<p>Welcome to the password protected area {$userSafe}</p>";
            echo "<img src=\"{$avatar}\" />";
        } else {
            echo "<pre><br />Username and/or password incorrect.</pre>";
        }
    } else {
        echo "<pre><br />Username and/or password incorrect.</pre>";
    }

    $stmt->close();
    $conn->close();
}
?>
