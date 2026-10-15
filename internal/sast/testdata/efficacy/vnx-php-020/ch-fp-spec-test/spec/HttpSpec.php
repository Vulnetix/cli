<?php
describe('http', function () {
    it('talks to the local stub', function () {
        $ch = curl_init('https://localhost:8443');
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    });
});
