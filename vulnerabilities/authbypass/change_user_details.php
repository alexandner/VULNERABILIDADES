<?php
define('DVWA_WEB_PAGE_TO_ROOT', '../../');
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaDatabaseConnect();

/*
  En nivel imposible sólo el admin puede acceder.
*/
if (dvwaSecurityLevelGet() == "impossible" && dvwaCurrentUser() != "admin") {
    print json_encode(array("result" => "fail", "error" => "Access denied"));
    exit;
}

if ($_SERVER['REQUEST_METHOD'] != "POST") {
    echo json_encode(array("result" => "fail", "error" => "Only POST requests are accepted"));
    exit;
}

try {
    $json = file_get_contents('php://input');
    $data = json_decode($json);

    if (is_null($data) || !isset($data->id, $data->first_name, $data->surname)) {
        echo json_encode(array(
            "result" => "fail",
            "error" => 'Invalid format, expecting "{id: {user ID}, first_name: \"{first name}\", surname: \"{surname}\"}"'
        ));
        exit;
    }

    // Validar que el ID es un número entero positivo
    $user_id = filter_var($data->id, FILTER_VALIDATE_INT, array("options" => array("min_range" => 1)));
    if ($user_id === false) {
        echo json_encode(array(
            "result" => "fail",
            "error" => "Invalid user ID"
        ));
        exit;
    }

    // Limpiar los strings para evitar caracteres problemáticos
    $first_name = trim($data->first_name);
    $surname = trim($data->surname);

    // Preparar la consulta para evitar SQL Injection
    $stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "UPDATE users SET first_name = ?, last_name = ? WHERE user_id = ?");
    if (!$stmt) {
        echo json_encode(array("result" => "fail", "error" => "Database error: prepare failed"));
        exit;
    }

    mysqli_stmt_bind_param($stmt, "ssi", $first_name, $surname, $user_id);

    if (!mysqli_stmt_execute($stmt)) {
        echo json_encode(array("result" => "fail", "error" => "Database error: execute failed"));
        exit;
    }

    mysqli_stmt_close($stmt);

    echo json_encode(array("result" => "ok"));
    exit;

} catch (Exception $e) {
    echo json_encode(array(
        "result" => "fail",
        "error" => 'Invalid format, expecting "{id: {user ID}, first_name: \"{first name}\", surname: \"{surname}\"}"'
    ));
    exit;
}
?>