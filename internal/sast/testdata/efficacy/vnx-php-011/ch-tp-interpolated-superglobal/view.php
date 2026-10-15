<?php
$conn = mysqli_connect('localhost', 'app', getenv('DB_PASS'), 'shop');
~>$result = mysqli_query($conn, "SELECT * FROM products WHERE id = '$_GET[id]'");
while ($row = mysqli_fetch_assoc($result)) {
    echo $row['name'];
}
