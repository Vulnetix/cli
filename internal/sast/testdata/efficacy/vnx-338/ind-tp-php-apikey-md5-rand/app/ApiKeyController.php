<?php

class ApiKeyController
{
    public function create(array $user): array
    {
~>        $apiKey = substr(md5(mt_rand() . $user['email']), 0, 32);
        $this->db->insert('api_keys', ['user_id' => $user['id'], 'key' => $apiKey]);
        return ['api_key' => $apiKey];
    }
}
