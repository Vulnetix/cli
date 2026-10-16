<?php
namespace App\Shipping;

class RateClient
{
    public function quote(array $parcel): array
    {
~>        $ch = curl_init('http://api.parcelrates.com/v3/quote');
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($parcel));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        return json_decode(curl_exec($ch), true);
    }
}
