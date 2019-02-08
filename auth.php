<?php
// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();
//error_reporting (E_ALL | E_STRICT);
//ini_set ('display_errors', 'On');
/**
 * authenticat against owncloud instance
 *
 * @license   GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author    Martin Schulte <lebowski[at]corvus[dot]uberspace[dot]de>
 * @author    Claus-Justus Heine <himself@claus-justus-heine.de>
 *
 * The current implementation uses the OC provisioning API. Note that
 * DokuWiki stores the user credentials in its cookies in a way that
 * they can be decrypted. This is questionable. OTOH, quite practical
 * here: just pass the user creds in each REST request. Other scheme
 * would be to remember the auth cookies.
 *
 */
class auth_plugin_authowncloud extends DokuWiki_Auth_Plugin
{
    protected $ownCloudUri; ///< from config space
    protected $authCookies; ///< from session
    protected $user; ///< cached user
    protected $password; ///< cached password

    public function __construct() {
        parent::__construct();

        $this->ownCloudUri = $this->getConf('ownclouduri');

        if (isset($_SESSION[DOKU_COOKIE]['authowncloud'])) {
            $this->authCookies = $_SESSION[DOKU_COOKIE]['authowncloud']['cookies'];
        } else {
            $this->authCookies = array();
        }
                
        $this->cando['addUser']   = true;
        $this->cando['modGroups'] = true;
        $this->cando['logout']    = true;
        $this->cando['delUser']   = true;
        $this->cando['modLogin']  = true;
        $this->cando['modPass']   = true;
        $this->cando['modName']   = true;
        $this->cando['modMail']   = true;
        $this->cando['getUsers']  = true;
        $this->cando['getGroups'] = true;
        $this->cando['getUserCount'] = true;
        $this->success = true;
    }

    protected function owncloudApiRequest($apiRequest, $method = 'GET', $params = array(), $user = null, $pass = null)
    {
        if (!$user || !$pass) {
            if ($this->user && $this->password) {
                $user = $this->user;
                $pass = $this->password;
            } else {
                list($user, $pass) = self::getCredentialsFromCookie();
                //error_log(__METHOD__.' credentials '.$one.' '.$two);
            }
        } else {
            $this->user = $user;
            $this->password = $pass;
        }
        
        $params = http_build_query($params, '', '&');
        $uri = $this->ownCloudUri.'/'.'ocs/v1.php/';
        $uri .= $apiRequest;
        $uri .= '?format=json';
        if ($method == 'GET') {
            $uri .= '&'.$params;
        }
        //error_log(__METHOD__.': '.$uri);

        $cookies = array();
        foreach($this->authCookies as $name => $value) {
            $cookies[] = $name.'='.urlencode($value);
        }
        $cookies = implode('; ', $cookies);

        $responseHeaders = array();
        if (function_exists('curl_version')) {
            $c = curl_init();
            curl_setopt($c, CURLOPT_VERBOSE, 1);
            curl_setopt($c, CURLOPT_URL, $uri);
            if ($user && $pass) {
                curl_setopt($c, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
                curl_setopt($c, CURLOPT_USERPWD, $user.':'.$pass);
                //error_log(__METHOD__.': '.$user.':'.$pass);
            }

            if ($method != 'GET') {
                curl_setopt($c, CURLOPT_POSTFIELDS, $params);
            }
            if ($method == 'PUT') {
                curl_setopt($c, CURLOPT_CUSTOMREQUEST, 'PUT');
            }
            if ($method == 'DELETE') {
                curl_setopt($c, CURLOPT_CUSTOMREQUEST, 'DELETE');
            }
            curl_setopt($c, CURLOPT_HTTPHEADER, array('OCS-ApiRequest: true'));
            curl_setopt($c, CURLOPT_HEADERFUNCTION,
                        function($curl, $headerline) use (&$responseHeaders) {
                            $responseHeaders[] = trim($headerline);
                            //error_log('header: '.$headerline);
                            return strlen($headerline);
                        });
            if (!empty($cookies)) {
                curl_setopt($c, CURLOPT_COOKIE, $cookies);
                //error_log(__METHOD__.': '.$cookies);
            }
            curl_setopt($c, CURLOPT_RETURNTRANSFER, 1);
            $responseBody = curl_exec($c);
            //error_log(__METHOD__.': '.print_r($responseBody, true));
            curl_close($c);
        } else {
            $headers = array();
            if ($user && $pass) {
                $headers[] = 'Authorization: Basic '.base64_encode($user.':'.$pass);
            }
            if ($method != 'GET') {
                $headers[] = 'Content-Type: application/x-www-form-urlencoded';
                $headers[] = 'Content-Length: '.strlen($params);
            }
            $headers[] = 'X-OCS-ApiRequest: 1';
            $headers[] = 'OCS-ApiRequest: 1';
            $headers[] = 'HTTP_OCS_APIREQUEST: true';
            if (!empty($cookies)) {
                $headers[] = 'Cookie: '.$cookie;
            }
            
            $http = array(
                'method' => $method,
                'header' => implode("\r\n", $headers)
                );
            if ($method != 'GET') {
                $http['content'] = $params;
            }
            $context = stream_context_create(array('http' => $http));
            $fp = fopen($uri, 'rb', false, $context);
            if ($fp === false) {
                return false;
            }
            $responseBody = stream_get_contents($fp);
            fclose($fp);
            $responseHeaders = $http_response_header;
        }
        $result = json_decode($responseBody, true);
        if (!is_array($result) ||
            !isset($result['ocs']) ||
            !isset($result['ocs']['data']) ||
            !isset($result['ocs']['meta']) ||
            !isset($result['ocs']['meta']['statuscode']) ||
            $result['ocs']['meta']['statuscode'] != 100) {
            //error_log(__METHOD__.' data '.print_r($result, true));
            return false;
        }
        $data = $result['ocs']['data'];

        //error_log(__METHOD__.' data '.print_r($data, true));
        
        /* parse the cookie headers and remember */
        foreach ($responseHeaders as $header) {
            $cookie = self::parseCookie($header);
            if (!$cookie) {
                continue;
            }
            if ($cookie['value'] == 'deleted') {
                continue;
            }
            if ($cookie['name'] == 'oc_sessionPassphrase') {
                $this->authCookies[$cookie['name']] = $cookie['value'];
                continue;
            }
            if (preg_match('/^(KEY_)?oc[a-z0-9]+/', $cookie['name'])) {
                $this->authCookies[$cookie['name']] = $cookie['value'];
                continue;
            }
        }

        $_SESSION[DOKU_COOKIE]['authowncloud']['cookies'] = $this->authCookies;
        
        return $data;
    }

    /**Obtain user and pass from the DokuWiki auth cookie, if set. */
    static protected function getCredentialsFromCookie()
    {
        // Encrypted password
        list($user, $sticky, $pass) = auth_getCookie();

        // Decrypt password
        $secret = auth_cookiesalt(!$sticky, true); //bind non-sticky to session
        //error_log(__METHOD__.' pass '.$pass.' secret '.$secret);
        $pass   = auth_decrypt($pass, $secret);
        //error_log(__METHOD__.' pass '.$pass.' secret '.$secret);

        return array($user, $pass);
    }
    
    /**
     * Parse a cookie header in order to obtain name, value, date of
     * expiry and path.
     *
     * @parm cookieHeader Guess what
     *
     * @return Array with name, value, expires and path fields, or
     * false if $cookie was not a Set-Cookie header.
     *
     */
    static protected function parseCookie($cookieHeader)
    {
        if (preg_match('/^Set-Cookie:\s*'.
                       '([^=]+)=([^;]+)(;|$)(\s*(expires)=([^;]+)(;|$))?(\s*(path)=([^;]+)(;|$))?/i',
                       $cookieHeader, $match)) {
            array_shift($match); // get rid of matched string
            $name = array_shift($match);
            $value = urldecode(array_shift($match));
            $path = false;
            $stamp = false;
            while (count($match) > 0) {
                $token = array_shift($match);
                switch ($token) {
                case 'expires':
                    $stamp = array_shift($match);
                    break;
                case 'path':
                    $path = array_shift($match);
                }
            }
            return array('name' => $name,
                         'value' => $value,
                         'expires' => $stamp,
                         'path' => $path);
        }
        return false;
    }
  
    /**
     * Check user+password
     *
     * Checks if the given user exists and the given
     * plaintext password is correct by forward it to
     * the corresponding owncloud function.
     *
     * @param string $user
     * @param string $pass
     * @return  bool
     */
    public function checkPass($user, $pass) {
        //error_log(__METHOD__);
        $data = $this->ownCloudApiRequest('cloud/users/'.$user, 'GET', array(), $user, $pass);
        return $data !== false; // if we succeed then this implies a successful login
    }

    /**
     * Return user info
     *
     * name string  full name of the user
     * mail string  email addres of the user
     * grps array   list of groups the user is in
     *
     * @param   string $user the user name
     * @return  array containing user data or false
     */
    public function getUserData($user, $requireGroups = true) {
        $data = $this->ownCloudApiRequest('cloud/users/'.$user);
        if (!is_array($data)) {
            return false;
        }
        $name = $data['displayname'];
        $mail = $data['email'];
        $result = array('name'=>$name, 'mail'=>$mail);
        if ($requireGroups) {
            $result['grps'] = $this->getUserGroups($user);
        }
        return $result;
    }

    /**
     * Create a new User
     *
     * Returns false if the user already exists, null when an error
     * occurred and true if everything went well.
     *
     * The new user will be added to the default group by this
     * function if grps are not specified (default behaviour).
     *
     *
     * @param string $user
     * @param string $pwd
     * @param string $name
     * @param string $mail
     * @param array  $grps
     * @return bool|null
     */
    public function createUser($user, $pwd, $name, $mail, $grps = null) {
        global $conf;
        if ($this->getUserData($user, false) !== false) {
            //error_log(__METHOD__.' user already present');
            return false;
        }
        $params = array('userid' => $user, 'password' => $pwd);
        $data = $this->ownCloudApiRequest('cloud/users', 'POST', $params);
        if ($data === false) {
            //error_log(__METHOD__.' cannot create user');
            return false;
        }
        $params = array('key' => 'display', 'value' => $name);
        $data = $this->ownCloudApiRequest('cloud/users/'.$user, 'PUT', $params);
        if ($data === false) {
            return false;
        }
        $params = array('key' => 'email', 'value' => $mail);
        $data = $this->ownCloudApiRequest('cloud/users/'.$user, 'PUT', $params);
        if ($data === false) {
            return false;
        }
        if(!is_array($grps)) $grps = array($conf['defaultgroup']);
        foreach($grps as $grp){
            $data = $this->retrieveGroups(0, -1, $grp);
            if (empty($data) && !$this->addGroup($grp)) {
                continue;
            }
            $params = array('groupid' => $grp);
            $data = $this->ownCloudApiRequest('cloud/users/'.$user.'/groups', 'POST', $params);
            if (!$data) {
                continue;
            }
        }

        return true;
    }


    /**
     * Modify user data
     *
     * @param   string $user      username
     * @param   array  $changes   array of field/value pairs to be changed
     * @return  bool
     */
    public function modifyUser($user, $changes) {
        //error_log(__METHOD__.' '.$user.' '.print_r($changes, true));
        foreach (array('mail' => 'email',
                       'name' => 'display',
                       'pass' => 'password') as $key => $ocKey) {
            if (!isset($changes[$key])) {
                continue;
            }
            $params = array('key' => $ocKey, 'value' => $changes[$key]);
            $data = $this->ownCloudApiRequest('cloud/users/'.$user, 'PUT', $params);
            if ($data === false) {
                return false;
            }
        }

        // groups need to be handled extra
        if (isset($changes['grps'])) {
            $oldGroups = $this->getUserGroups($user);
            foreach ($changes['grps'] as $grp){
                $data = $this->retrieveGroups(0, -1, $grp);
                if (empty($data) && !$this->addGroup($grp)) {
                    continue;
                }
                $params = array('groupid' => $grp);
                $data = $this->ownCloudApiRequest('cloud/users/'.$user.'/groups', 'POST', $params);
                if (!$data) {
                    continue;
                }
            }
            $deletedGroups = array_diff($oldGroups, $changes['grps']);
            foreach ($deletedGroups as $grp) {
                $params = array('groupid' => $grp);
                $data = $this->ownCloudApiRequest('cloud/users/'.$user.'/groups', 'DELETE', $params);
                if (!$data) {
                    continue;
                }
            }
        }

        return true;
    }


    /**
     * Remove one or more users from the owncloud database
     *
     * @param   array  $users   array of users to be deleted
     * @return  int             the number of users deleted
     */
    public function deleteUsers($users) {
        $deleted = 0;
        foreach($users as $user) {
            $data = $this->ownCloudApiRequest('cloud/users/'.$user, 'DELETE');
            if ($data !== false) {
                ++$deleted;
            }
        }
        return $deleted;
    }

    /**
     * Return a count of the number of user which meet $filter criteria
     *
     * @author  Chris Smith <chris@jalakai.co.uk>
     *
     * @param array $filter
     * @return int
     */
    public function getUserCount($filter = array()){
        $data = $this->ownCloudApiRequest('cloud/users');
        if (!isset($data['users'])) {
            return false;
        }
        $users = $data['users'];
        return count($users);
    }

    /**
     * Bulk retrieval of user data
     *
     *
     * @param   int   $start index of first user to be returned
     * @param   int   $limit max number of users to be returned
     * @param   array $filter array of field/pattern pairs
     * @return  array userinfo (refer getUserData for internal userinfo details)
     */
    public function retrieveUsers($start = 0, $limit = -1, $filter = array()) {
        $params = array('offset' => $start);
        if ($limit >= 0) {
            $params['limit'] = $limit;
        }
        if (isset($filter['user'])) {
            $params['search'] = $filter['user'];
        }
        $data = $this->ownCloudApiRequest('cloud/users', 'GET', $params);
        if (!isset($data['users'])) {
            return false;
        }
        $users = $data['users'];
        $ret = array();
        foreach ($users as $user) {
            $data = $this->getUserData($user);
            $inc = true;
            foreach ($filter as $key => $pattern) {
                if (strstr($data[$key], $pattern) === false) {
                    $inc = false;
                    break;
                }
            }
            if ($inc) { // else discard
                $ret[$user] = $data;
            }
        }
        //error_log(__METHOD__.' '.print_r($ret, true));
        return $ret;
    }
        
    /**
     * Define a group
     *
     * @param   string $group
     * @return  bool success
     */
    public function addGroup($group) {
        $params = array('groupid' => $group);
        $data = $this->ownCloudApiRequest('cloud/groups', 'POST', $params);
        return $data !== false;
    }


    /**
     * LogOff user
     */
    public function logOff() {
        // we simply unset auth cookies
        unset($_SESSION[DOKU_COOKIE]['authowncloud']);
        $this->authCookies = array();
    }

    /* List all available groups
     *
     * @return array|bool false or array with all groups.
     */
    public function retrieveGroups($start = 0, $limit = -1, $search = false) {
        $params = array('offset' => $start);
        if ($limit >= 0) {
            $params['limit'] = $limit;
        }
        if ($search) {
            $params['search'] = $search;
        }
        $data = $this->ownCloudApiRequest('cloud/groups', 'GET', $params);
        if (!isset($data['groups'])) {
            return false;
        }
        //error_log(__METHOD__.' '.print_r($data['groups'], true));
        return $data['groups'];
    }

    /* List all available groups for a user (not part of the auth interface)
     *
     * @param string $user loginname
     * @return array|bool false or array with all groups of this user.
     */
    private function getUserGroups($user){
        $data = $this->ownCloudApiRequest('cloud/users/'.$user.'/groups');
        if (!isset($data['groups'])) {
            return false;
        }
        //error_log(__METHOD__.' '.print_r($data['groups'], true));
        return $data['groups'];
    }
}

/*
 * Local Variables: ***
 * c-basic-offset: 4 ***
 * End: ***
 */
