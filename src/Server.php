<?php

namespace On2Media\OAuth2SSOServer;

class Server
{
    private $pdo;

    private $timeout;

    private $storage;

    private $server;

    public function __construct($pdo, $timeout)
    {
        $this->pdo = $pdo;
        $this->timeout = $timeout;
        $this->storage = new AppStorage($this->pdo);

        $this->server = new \OAuth2\Server(
            $this->storage,
            [
                'refresh_token_lifetime' => $this->timeout,
            ]
        );

        $this->server->addGrantType(new \OAuth2\GrantType\AuthorizationCode($this->storage));

        $grantType = new \OAuth2\GrantType\RefreshToken(
            $this->storage,
            [
                'unset_refresh_token_after_use' => false,
            ]
        );
        $this->server->addGrantType($grantType);

        $grantType = new \OAuth2\GrantType\UserCredentials($this->storage);
        $this->server->addGrantType($grantType);

        $this->server->addGrantType(new \OAuth2\GrantType\ClientCredentials($this->storage));

        if (isset($_SESSION['user'])) {

            if ($this->checkTimeout($_SESSION['user']['user_id'])) {

                // update last activity for self

                $sth = $this->pdo->prepare('SELECT COUNT(*) FROM oauth_user_sessions WHERE user_id = ? AND client_id IS NULL AND session_id = ?');
                $sth->execute([$_SESSION['user']['user_id'], session_id()]);

                if ($sth->fetchColumn() == 0) {
                    $this->signOut($_SESSION['user']['user_id'], session_id());
                } else {
                    $sth = $this->pdo->prepare('UPDATE oauth_user_sessions SET last_activity = ? WHERE user_id = ? AND client_id IS NULL AND session_id = ?');
                    $sth->execute([date('Y-m-d H:i:s'), $_SESSION['user']['user_id'], session_id()]);
                    $this->extendRefreshTokenValidity(session_id());
                }

            }

        }
    }

    public function extendRefreshTokenValidity($sessionId)
    {
        $sth = $this->pdo->prepare(
            'UPDATE oauth_refresh_tokens SET expires = ? WHERE refresh_token IN (
                SELECT refresh_token FROM oauth_user_sessions
                WHERE session_id = ? AND refresh_token IS NOT NULL
            )'
        );
        $sth->execute(
            [
                date('Y-m-d H:i:s', time() + $this->timeout),
                $sessionId,
            ]
        );
    }

    public function checkTimeout($userId, $sessionId = null)
    {
        if ($sessionId === null) {
            $sessionId = session_id();
        }

        if ($this->timeout > 0) {

            $sth = $this->pdo->prepare('SELECT UNIX_TIMESTAMP(last_activity) FROM oauth_user_sessions WHERE user_id = ? AND session_id = ?');
            $sth->execute([$userId, $sessionId]);
            $lastClientActivities = $sth->fetchAll(\PDO::FETCH_COLUMN);
            if (count($lastClientActivities) == 0 || (!$lastClientActivity = max($lastClientActivities))) {
                $lastClientActivity = time();
            }
            if (time() - $lastClientActivity > $this->timeout) {
                if (isset($_SESSION['user'])) {
                    $_SESSION['timed_out'] = true;
                }
                $this->signOut($userId, $sessionId);
                return false;
            }
        }

        return true;
    }

    public function getTeams($userId, $clientId = null)
    {
        $teams = $this->storage->fetchTeams($userId);

        $rtn = [];
        foreach ($teams as $teamId => $teamClients) {
            if (!isset($rtn[$teamId])) {
                $firstTeamClient = reset($teamClients);
                $rtn[$teamId] = [
                    'id' => $teamId,
                    'name' => $firstTeamClient['team_name'],
                    'logo' => $firstTeamClient['team_logo'],
                    'clients' => [],
                ];
                $teamClientTypes = [];
                foreach ($teamClients as $teamClient) {
                    if (!isset($teamClientTypes[$teamClient['client_type_id']])) {
                        $teamClientTypes[$teamClient['client_type_id']] = 0;
                    }
                    $teamClientTypes[$teamClient['client_type_id']]++;
                }
                foreach ($teamClients as $teamClient) {
                    $rtn[$teamId]['clients'][] = [
                        'id' => $teamClient['client_id'],
                        'name' => ($teamClientTypes[$teamClient['client_type_id']] == 1
                            ? $teamClient['client_type_name']
                            : sprintf('%s for %s', $teamClient['client_type_name'], $teamClient['client_name'])
                        ),
                        'href' => $teamClient['client_href'],
                        'type' => $teamClient['client_type_name'],
                        'logo' => $teamClient['client_type_logo'],
                        'brandmark' => $teamClient['client_type_brandmark'],
                    ];
                    if ($clientId !== null && $teamClient['client_id'] == $clientId) {
                        $rtn[$teamId]['active'] = true;
                    }
                }
            }
        }

        return array_values($rtn);
    }

    public function getLoneWolves($userId)
    {
        $clients = $this->storage->fetchLoneWolves($userId);

        $clientTypes = [];
        foreach ($clients as $client) {
            if (!isset($clientTypes[$client['client_type_id']])) {
                $clientTypes[$client['client_type_id']] = 0;
            }
            $clientTypes[$client['client_type_id']]++;
        }

        $rtn = [];
        foreach ($clients as $client) {
            $rtn[] = [
                'id' => $client['client_id'],
                'name' => ($clientTypes[$client['client_type_id']] == 1
                    ? $client['client_type_name']
                    : sprintf('%s for %s', $client['client_type_name'], $client['client_name'])
                ),
                'href' => $client['client_href'],
                'type' => $client['client_type_name'],
                'logo' => $client['client_type_logo'],
                'brandmark' => $client['client_type_brandmark'],
            ];
        }
        return $rtn;
    }

    public function getClientTeams($clientId, $userId = null)
    {
        if ($userId === null) {
            return $this->storage->fetchAllClientTeams($clientId);
        }
        return $this->storage->fetchClientTeamsForUser($clientId, $userId);
    }

    public function handleSignIn($base)
    {
        $queryAdditions = [];

        if (isset($_GET['sso'])) {
            // clear any incomplete authorization code grants
            unset($_SESSION['oauth2_request']);
        }

        if (isset($_GET['sso'])) {
            $client = $this->ssoSignIn();
        }

        if (isset($_POST['username'], $_POST['password'])) {

            if (!$this->storage->checkUserCredentials($_POST['username'], $_POST['password'])) {
                if (!isset($_GET['sso'])) {
                    $_SESSION['just_failed'] = $_POST['username'];
                }
                $queryAdditions = ['success' => 'false'];
            } else {

                $_SESSION['user'] = $this->storage->getUser($_POST['username']);

                $sth = $this->pdo->prepare('SELECT COUNT(*) FROM oauth_user_sessions WHERE user_id = ? AND client_id IS NULL AND session_id = ?');
                $sth->execute([$_SESSION['user']['user_id'], session_id()]);

                if ($sth->fetchColumn() == 0) {
                    $sth = $this->pdo->prepare('INSERT INTO oauth_user_sessions (user_id, client_id, session_id, started_at, last_activity) VALUES (?, NULL, ?, ?, ?)');
                    $sth->execute([$_SESSION['user']['user_id'], session_id(), date('Y-m-d H:i:s'), date('Y-m-d H:i:s')]);
                } else {
                    $sth = $this->pdo->prepare('UPDATE oauth_user_sessions SET started_at = ?, last_activity = ? WHERE user_id = ? AND client_id IS NULL AND session_id = ?');
                    $sth->execute([date('Y-m-d H:i:s'), date('Y-m-d H:i:s'), $_SESSION['user']['user_id'], session_id()]);
                }

                $queryAdditions = ['success' => 'true'];

                if (isset($_SESSION['oauth2_request'])) {
                    $q = http_build_query($_SESSION['oauth2_request']);
                    header('Location: ' . $base . '/authorize?' . $q);
                    exit();
                }

            }

            if (!isset($_GET['sso'])) {
                header('Location: ' . $base . '/');
                exit();
            }

        } elseif (isset($_SESSION['user'])) {
            $queryAdditions = ['success' => 'true'];
        } else {
            $queryAdditions = ['success' => 'false', 'welcome' => '1'];
        }

        if (isset($_GET['sso'])) {
            self::ssoRedirect($client['sso_auth_url'], $queryAdditions);
        }

        if (isset($_SESSION['user'])) {
            header('Location: ' . $base . '/');
            exit();
        }

        if (isset($_SESSION['oauth2_request'])) {
            $sth = $this->pdo->prepare('
                SELECT oauth_client_types.name AS type, oauth_clients.name AS name, oauth_client_types.logo AS logo
                FROM oauth_clients
                LEFT JOIN oauth_client_types ON oauth_clients.client_type_id = oauth_client_types.client_type_id
                WHERE client_id = ?
            ');
            $sth->execute([$_SESSION['oauth2_request']['client_id']]);
            return $sth->fetch(\PDO::FETCH_ASSOC);
        }
    }

    public function handleAuthoriseRequest($base)
    {
        if (isset($_GET['just_timed_out'])) {
            $_SESSION['timed_out'] = true;
        }
        return (new AuthoriseRequest($this->server, $this->pdo))->handle($base);
    }

    public function handleTokenRequest()
    {
        (new TokenRequest($this->server, $this->pdo))->handle();
    }

    public function handleResourceRequest()
    {
        (new ResourceRequest($this->server, $this->pdo))->handle($this);
    }

    public function ssoSignIn()
    {
        if (!isset($_GET['client']) || !$client = $this->storage->getClientDetails($_GET['client'])) {
            exit('unauthorized - bad client');
        }

        if (!isset($_GET['nonce'], $_GET['hash'])) {
            exit('no nonce or hash');
        }

        $hash = hash_hmac(
            'sha1',
            $_GET['client'] . $_GET['nonce'],
            $client['client_secret']
        );

        if ($hash != $_GET['hash']) {
            exit('unauthorized - bad hash');
        }

        $timestamp = hexdec(substr($_GET['nonce'], 0, 8));

        if (abs(time() - $timestamp) > 60 * 15) {
            exit('unauthorized - too slow');
        }

        return $client;
    }

    public function signOut($userId, $sessionId)
    {
        $sth = $this->pdo->prepare('SELECT access_token, refresh_token FROM oauth_user_sessions WHERE user_id = ? AND session_id = ?');
        $sth->execute([$userId, $sessionId]);
        $tokens = $sth->fetchAll(\PDO::FETCH_ASSOC);

        foreach ($tokens as $token) {

            $this->storage->unsetAccessToken($token['access_token']);
            $this->storage->unsetRefreshToken($token['refresh_token']);

        }

        $sth = $this->pdo->prepare('DELETE FROM oauth_user_sessions WHERE user_id = ? AND session_id = ?');
        $sth->execute([$userId, $sessionId]);

        if (isset($_SESSION['user'])) {
            unset($_SESSION['user']);
        }
    }

    public static function ssoRedirect($clientUrl, $queryAdditions = [])
    {
        $ssoAuthUrl = parse_url($clientUrl);
        if (isset($ssoAuthUrl['query'])) {
            parse_str($ssoAuthUrl['query'], $ssoQueryParts);
            $ssoQueryParts += $queryAdditions;
        } else {
            $ssoQueryParts = $queryAdditions;
        }

        $rtnUrl = sprintf(
            '%s//%s%s%s%s%s%s',
            (isset($ssoAuthUrl['scheme']) ? $ssoAuthUrl['scheme'] . ':' : ''),
            (isset($ssoAuthUrl['user'], $ssoAuthUrl['pass']) ? $ssoAuthUrl['user'] . ':' . $ssoAuthUrl['pass'] . '@' : ''),
            $ssoAuthUrl['host'],
            (isset($ssoAuthUrl['port']) ? ':' . $ssoAuthUrl['port'] : ''),
            $ssoAuthUrl['path'],
            ($ssoQueryParts == [] ? '' : '?' . http_build_query($ssoQueryParts)),
            (isset($ssoAuthUrl['fragment']) ? '#' . $ssoAuthUrl['fragment'] : '')
        );

        header('Location: ' . $rtnUrl);
        exit();
    }
}
