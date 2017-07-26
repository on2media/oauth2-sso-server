<?php

namespace On2Media\OAuth2SSOServer;

class AppStorage extends \OAuth2\Storage\Pdo
{
    protected function checkPassword($user, $password)
    {
        return password_verify($password, $user['password']);
    }
}

// @todo addUser and rehashing -- // echo password_hash('password', PASSWORD_DEFAULT);
