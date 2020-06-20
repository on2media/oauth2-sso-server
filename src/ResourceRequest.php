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
        $request = \OAuth2\Request::createFromGlobals();

        // Handle a request to a resource and authenticate the access token
        if (!$this->server->verifyResourceRequest($request)) {
            $this->server->getResponse()->send();
            die;
        }

        $accessTokenData = $this->server->getAccessTokenData($request);

        if ($accessTokenData['user_id'] === null) {

            $sessionId = false;
            $user = null;

        } else {

            $sth = $this->pdo->prepare('SELECT session_id, refresh_token FROM oauth_user_sessions WHERE user_id = ? AND client_id = ? AND access_token = ?');
            $sth->execute(
                [
                    $accessTokenData['user_id'],
                    $accessTokenData['client_id'],
                    $accessTokenData['access_token'],
                ]
            );
            $sessionData = $sth->fetch(\PDO::FETCH_ASSOC);
            $sessionId = $sessionData['session_id'] ?? false;

            $sth = $this->pdo->prepare('SELECT * FROM oauth_users WHERE username = ?');
            $sth->execute([$accessTokenData['user_id']]);
            $user = $sth->fetch(\PDO::FETCH_ASSOC);

        }

        if ($sessionId) {

            if (!$ssoServer->checkTimeout($accessTokenData['user_id'], $sessionId)) {

                $response = new \OAuth2\Response();
                $response->setError(401, 'invalid_token', 'The access token provided is invalid');
                $response->send();
                exit();

            }

            $extendTimeout = ($request->headers('KEEP_TIMEOUT') != '1');

            if ($extendTimeout) {

                $lastActivityTime = new \DateTime();

                $sth = $this->pdo->prepare('UPDATE oauth_user_sessions SET last_activity = ? WHERE user_id = ? AND client_id = ? AND access_token = ?');
                $sth->execute(
                    [
                        $lastActivityTime->format('Y-m-d H:i:s'),
                        $accessTokenData['user_id'],
                        $accessTokenData['client_id'],
                        $accessTokenData['access_token'],
                    ]
                );

            } else {

                $sth = $this->pdo->prepare('SELECT MAX(last_activity) FROM oauth_user_sessions WHERE session_id = ?');
                $sth->execute([$sessionId]);
                $lastActivityTime = \DateTime::createFromFormat('Y-m-d H:i:s', $sth->fetchColumn());

            }

            if ($sessionData['refresh_token'] !== null) {
                $ssoServer->extendRefreshTokenValidity($sessionId);
            }

            $timeout = clone($lastActivityTime);
            $timeout->add(
                new \DateInterval('PT' . $this->server->getConfig('refresh_token_lifetime') . 'S')
            );

            $timeoutData = [
                'seconds' => $this->server->getConfig('refresh_token_lifetime'),
                'due_at' => $timeout->format(\DateTime::ATOM),
            ];

        }

        $output = [
            'id' => $accessTokenData['user_id'],
            'initials' => $user['initials'] ?? null,
            'name' => $user['name'] ?? null,
            'email' => $user['email'] ?? null,
            'avatar' => $user['avatar'] ?? null,
            'your_client_id' => $accessTokenData['client_id'],
            'timeout' => $timeoutData ?? null,
            'available_clients' => [],
            'teams' => $ssoServer->getTeams(
                $accessTokenData['user_id'],
                $accessTokenData['client_id']
            ),
        ];

        if ($output['timeout'] === null) {
            unset($output['timeout']);
        }

        header('Content-Type: application/json');
        echo json_encode($output);
    }
}
