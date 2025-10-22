<?php

http_response_code(404);

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Page Not Found</title>
    <style>
        body {
            background-color: #f4f4f4;
            font-family: Arial, sans-serif;
            text-align: center;
            padding-top: 10%;
            color: #333;
        }
        h1 {
            font-size: 3em;
            margin-bottom: 0.2em;
        }
        p {
            font-size: 1.2em;
            color: #666;
        }
        a {
            display: inline-block;
            margin-top: 2em;
            text-decoration: none;
            color: #007BFF;
            font-weight: bold;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
<h1>404</h1>
<p>Sorry, the page you’re looking for doesn’t exist.</p>
<a href="/">Return to Home</a>
</body>
</html>
