<?php

namespace On2Media\OAuth2SSOServer;

class ResourceRequest
{
    private $server;

    private $pdo;

    public function __construct($server, $pdo)
    {
        $this->server = $server;
        $this->pdo = $pdo;
    }

    public function handle($ssoServer)
    {
        // Handle a request to a resource and authenticate the access token
        if (!$this->server->verifyResourceRequest(\OAuth2\Request::createFromGlobals())) {
            $this->server->getResponse()->send();
            die;
        }

        $accessTokenData = $this->server->getAccessTokenData(\OAuth2\Request::createFromGlobals());

        $sth = $this->pdo->prepare('SELECT session_id FROM oauth_user_sessions WHERE user_id = ? AND client_id = ? AND access_token = ?');
        $sth->execute(
            [
                $accessTokenData['user_id'],
                $accessTokenData['client_id'],
                $accessTokenData['access_token'],
            ]
        );
        $sessionId = $sth->fetchColumn();

        $sth = $this->pdo->prepare('SELECT * FROM oauth_users WHERE username = ?');
        $sth->execute([$accessTokenData['user_id']]);
        $user = $sth->fetch(\PDO::FETCH_ASSOC);

        if ($sessionId) {

            if (!$ssoServer->checkTimeout($accessTokenData['user_id'], $sessionId)) {

                $response = new \OAuth2\Response();
                $response->setError(401, 'invalid_token', 'The access token provided is invalid');
                $response->send();
                exit();

            }

            $sth = $this->pdo->prepare('UPDATE oauth_user_sessions SET last_activity = ? WHERE user_id = ? AND client_id = ? AND access_token = ?');
            $sth->execute(
                [
                    date('Y-m-d H:i:s'),
                    $accessTokenData['user_id'],
                    $accessTokenData['client_id'],
                    $accessTokenData['access_token'],
                ]
            );

        }

        $availableClients = $ssoServer->getAvailabileClients($accessTokenData['user_id'], $this->pdo);

        header('Content-Type: application/json');

        echo json_encode(
            [
                'id' => $accessTokenData['user_id'],
                'name' => $user['name'],
                'email' => $user['email'],
                'your_client_id' => $accessTokenData['client_id'],
                'available_clients' => $availableClients,
            ]
        );
    }
}
