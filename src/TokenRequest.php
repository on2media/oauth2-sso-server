<?php

namespace On2Media\OAuth2SSOServer;

class TokenRequest
{
    private $server;

    private $pdo;

    public function __construct($server, $pdo)
    {
        $this->server = $server;
        $this->pdo = $pdo;
    }

    public function handle()
    {
        // Handle a request for an OAuth2.0 Access Token and send the response to the client
        $request = \OAuth2\Request::createFromGlobals();
        $response = $this->server->handleTokenRequest($request);

        if ($response->isSuccessful()) {

            if ($request->request('code') !== null) {

                // access_token
                $sth = $this->pdo->prepare('UPDATE oauth_user_sessions SET authorization_code = NULL, refresh_token = ?, access_token = ? WHERE authorization_code = ?');
                $sth->execute(
                    [
                        $response->getParameter('refresh_token'),
                        $response->getParameter('access_token'),
                        $request->request('code')
                    ]
                );

            } elseif ($request->request('refresh_token') !== null) {

                // refresh_token
                $sth = $this->pdo->prepare('UPDATE oauth_user_sessions SET authorization_code = NULL, access_token = ? WHERE refresh_token = ?');
                $sth->execute(
                    [
                        $response->getParameter('access_token'),
                        $request->request('refresh_token')
                    ]
                );

            }

            if ($_POST['grant_type'] == 'password') {

                $clientId = $this->server->getClientAssertionType()->getClientId();

                $sth = $this->pdo->prepare('SELECT * FROM oauth_user_clients WHERE user_id = ? AND client_id = ?');
                $sth->execute([$_POST['username'], $clientId]);

                if (!$userClient = $sth->fetch(\PDO::FETCH_ASSOC)) {

                    $sth = $this->pdo->prepare('INSERT INTO oauth_user_clients (user_id, client_id, authorized_at) VALUES (?, ?, ?)');
                    $sth->execute([$_POST['username'], $clientId, date('Y-m-d H:i:s')]);

                }

            }

        }

        $response->send();

        // $this->server->grantAccessToken() ???
    }
}
