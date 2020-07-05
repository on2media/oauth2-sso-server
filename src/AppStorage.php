<?php

namespace On2Media\OAuth2SSOServer;

class AppStorage extends \OAuth2\Storage\Pdo
{
    protected function checkPassword($user, $password)
    {
        return password_verify($password, $user['password']);
    }

    public function fetchTeams($user_id)
    {
        $sql = <<<SQL
SELECT
    t.team_id,
    t.name AS team_name,
    t.logo AS team_logo,
    c.client_id,
    c.name AS client_name,
    CONCAT(c.sso_home_url, IF(c.suffix_team_id_to_home_url = 1, CONCAT("/", t.team_id), "")) AS client_href,
    cty.client_type_id,
    cty.name AS client_type_name,
    cty.logo AS client_type_logo,
    cty.brandmark AS client_type_brandmark
FROM oauth_user_teams AS ut
LEFT JOIN oauth_client_teams AS ct ON ct.team_id = ut.team_id
LEFT JOIN oauth_teams AS t ON t.team_id = ut.team_id
LEFT JOIN oauth_clients AS c ON c.client_id = ct.client_id
LEFT JOIN oauth_client_types AS cty ON cty.client_type_id = c.client_type_id
LEFT JOIN oauth_user_clients AS uc ON uc.user_id = ut.user_id AND uc.client_id = c.client_id
WHERE ut.user_id = :user_id AND uc.user_id IS NOT NULL
ORDER BY t.team_id, c.name
SQL;

        $stmt = $this->db->prepare($sql);
        $stmt->execute(compact('user_id'));
        return $stmt->fetchAll(\PDO::FETCH_ASSOC|\PDO::FETCH_GROUP);
    }

    public function fetchLoneWolves($user_id)
    {
        $sql = <<<SQL
SELECT
    c.client_id,
    c.name AS client_name,
    c.sso_home_url AS client_href,
    cty.client_type_id,
    cty.name AS client_type_name,
    cty.logo AS client_type_logo,
    cty.brandmark AS client_type_brandmark,
    uc.*
FROM oauth_clients AS c
LEFT JOIN oauth_client_teams AS ct ON ct.client_id = c.client_id
LEFT JOIN oauth_client_types AS cty ON cty.client_type_id = c.client_type_id
LEFT JOIN oauth_user_clients AS uc ON uc.client_id = c.client_id
WHERE ct.client_id IS NULL AND uc.user_id = :user_id
ORDER BY c.name
SQL;

        $stmt = $this->db->prepare($sql);
        $stmt->execute(compact('user_id'));
        return $stmt->fetchAll(\PDO::FETCH_ASSOC);
    }

    public function fetchAllClientTeams($client_id)
    {
        $stmt = $this->db->prepare('SELECT team_id FROM oauth_client_teams WHERE client_id = :client_id');
        $stmt->execute(compact('client_id'));
        return $stmt->fetchAll(\PDO::FETCH_COLUMN);
    }

    public function fetchClientTeamsForUser($client_id, $user_id)
    {
        $sql = <<<SQL
SELECT DISTINCT ct.team_id
FROM oauth_client_teams AS ct
LEFT JOIN oauth_user_teams AS ut ON ut.team_id = ct.team_id
WHERE ct.client_id = :client_id  AND ut.user_id = :user_id
SQL;

        $stmt = $this->db->prepare($sql);
        $stmt->execute(compact('client_id', 'user_id'));
        return $stmt->fetchAll(\PDO::FETCH_COLUMN);
    }
}

// @todo addUser and rehashing -- // echo password_hash('password', PASSWORD_DEFAULT);
