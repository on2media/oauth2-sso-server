<?php

namespace On2Media\OAuth2SSOServer;

class AuthoriseRequest
{
    private $server;

    private $pdo;

    public function __construct($server, $pdo)
    {
        $this->server = $server;
        $this->pdo = $pdo;
    }

    public function handle($base)
    {
        $request = \OAuth2\Request::createFromGlobals();
        $response = new \OAuth2\Response();

        // validate the authorize request
        if (!$this->server->validateAuthorizeRequest($request, $response)) {
            $response->send();
            die;
        }

        $_SESSION['oauth2_request'] = $request->getAllQueryParameters();

        if (!isset($_SESSION['user'])) {
            header('Location: ' . $base . '/sign-in');
            exit();
        }

        // var_dump($_POST, !isset($_POST['authorized']));

        // display an authorization form
        if (!isset($_POST['authorized'])/* || $_POST['authorized'] == 'No'*/) {

            $sth = $this->pdo->prepare('SELECT * FROM oauth_user_clients WHERE user_id = ? AND client_id = ?');
            $sth->execute([$_SESSION['user']['username'], $_GET['client_id']]);

            if ($userClient = $sth->fetch(\PDO::FETCH_ASSOC)) {
                $_POST['authorized'] = 'Yes';
            } else {

                $sth = $this->pdo->prepare('SELECT
                    oauth_client_types.name AS type,
                    oauth_clients.name AS name
                FROM oauth_clients
                LEFT JOIN oauth_client_types ON oauth_client_types.client_type_id = oauth_clients.client_type_id
                WHERE oauth_clients.client_id = ?');
                $sth->execute([$_GET['client_id']]);

                if (!$client = $sth->fetch(\PDO::FETCH_ASSOC)) {
                    exit('invalid client');
                }

                // show authorisation request to user
                return $client;

            }
        }

        // print the authorization code if the user has authorized your client
        $is_authorized = ($_POST['authorized'] === 'Yes');
        $userid = $_SESSION['user']['username'];
        $this->server->handleAuthorizeRequest($request, $response, $is_authorized, $userid);
        if ($is_authorized) {
          // this is only here so that you get to see your code in the cURL request. Otherwise, we'd redirect back to the client
          $code = substr($response->getHttpHeader('Location'), strpos($response->getHttpHeader('Location'), 'code=')+5, 40);
          // exit("SUCCESS! Authorization Code: $code");

            $clientId = $this->server->getAuthorizeController()->getClientId();

            $sth = $this->pdo->prepare('SELECT COUNT(*) FROM oauth_user_sessions WHERE user_id = ? AND client_id = ? AND session_id = ?');
            $sth->execute([$userid, $clientId, session_id()]);

            if ($sth->fetchColumn() == 0) {
                $sth = $this->pdo->prepare('INSERT INTO oauth_user_sessions (user_id, client_id, session_id, authorization_code, access_token, started_at, last_activity) VALUES (?, ?, ?, ?, NULL, ?, ?)');
                $sth->execute([$userid, $clientId, session_id(), $code, date('Y-m-d H:i:s'), date('Y-m-d H:i:s')]);
            } else {
                $sth = $this->pdo->prepare('UPDATE oauth_user_sessions SET authorization_code = ?, access_token = NULL, started_at = ?, last_activity = ? WHERE user_id = ? AND client_id = ? AND session_id = ?');
                $sth->execute([$code, date('Y-m-d H:i:s'), date('Y-m-d H:i:s'), $userid, $clientId, session_id()]);
            }

            if (!isset($userClient) || $userClient === false) {

                $sth = $this->pdo->prepare('INSERT INTO oauth_user_clients (user_id, client_id, authorized_at) VALUES (?, ?, ?)');
                $sth->execute([$userid, $clientId, date('Y-m-d H:i:s')]);

            }

            unset($_SESSION['oauth2_request']);

        }
        $response->send();
        exit;
    }
}
