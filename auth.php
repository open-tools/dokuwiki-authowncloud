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
 */
class auth_plugin_authowncloud extends DokuWiki_Auth_Plugin {
   
	public function __construct() {
		parent::__construct();

        $savedSession = session_name();
        session_write_close();
        // one could argue about error_reportint() .... ;) However, we
        // simply save and restore the settings active in
        // owncloud. Otherwise the owncloud.log will be bloated with
        // all kind of DW warnings
        $savedReporting = error_reporting();

		require_once($this->getConf('pathtoowncloud').'/lib/base.php');

        error_reporting($savedReporting);
        error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED & ~E_STRICT);
        session_write_close();
        session_name($savedSession);
        session_start();

		// Check if ownCloud is installed or in maintenance (update) mode
		if (!OC_Config::getValue('installed', false)) {
			global $conf;
			echo "Owncloud not installed!";
			$this->success = false;
		}else{
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
         if(OC_USER::checkPassword($user,$pass)) return true;
         return false;
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
    public function getUserData($user) {
		$name = OC_User::getDisplayName($user);
		$mail = $this->getUserMail($user);
		$grps = $this->getUserGroups($user);
        return array('name'=>$name,'mail'=>$mail,'grps'=>$grps);
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
		if(OC_USER::userExists($user)) return false;
		if(!OC_USER::createUser($user, $pwd)) return null;
		if(!OC_USER::setDisplayName($user, $name)) return null;
        if(!OC_Preferences::setValue($user, 'settings', 'email', $mail)) return null;
        if(!OC_Group::groupExists($conf['defaultgroup'])) $this->addGroup($conf['defaultgroup']);
        if(!is_array($grps)) $grps = array($conf['defaultgroup']);
        foreach($grps as $grp){
			if(!OC_Group::groupExists($grp)) $this->addGroup($grp);
			OC_Group::addToGroup($user, $grp);
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
        $return = true;
        // password changing
        if(isset($changes['pass'])) {
			if(!OC_User::setPassword($user, $changes['pass'])) return false;
        }
        // changing user data
        $adchanges = array();
        if(isset($changes['name'])) {
            if(!OC_USER::setDisplayName($user, $changes['name'])) return false;
        }
        if(isset($changes['grps'])) {
			foreach($changes['grps'] as $grp){
				if(!OC_Group::groupExists($grp)) $this->addGroup($grp);
				OC_Group::addToGroup($user, $grp);
			}
        }
        if(isset($changes['mail'])) {
            if(!OC_Preferences::setValue($user, 'settings', 'email', $changes['mail'])) return false;
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
        if(!is_array($users) || empty($users)) return 0;
        $deleted = 0;
        foreach($users as $user) {
            if(OC_User::deleteUser($user)) $deleted++;
        }
        return $deleted;
    }
    
    
    /**
     * Return db-query for filter
     *
     *
     * @param array $filter
     * @return int
     */
    private function getUsers($filter = array(), $start = 0, $limit = -1) {
		$wheres = '';
		$joins = '';
		$selectMail = '';
		$selectGroup = '';
		if(!empty($filter)){
			foreach($filter as $item => $pattern) {
				$where = array();
				$values = array();
				$groupJoin = false;
				$prefJoin = false;
				$tmp = "%$pattern%";
				if($item == 'user') {
					array_push($where, '*PREFIX*users.uid LIKE ?');
					array_push($values, $tmp);
				}else if($item == 'name') {
					array_push($where, '*PREFIX*users.displayname LIKE ?');
					array_push($values, $tmp);
				}else if($item == 'mail') {
					array_push($where, '*PREFIX*preferences.configvalue LIKE ?');
					array_push($values, $tmp);
					$prefJoin = true;
				}else if($item == 'grps') {
					array_push($where, '*PREFIX*group_user.gid LIKE ?');
					array_push($values, $tmp);
					$groupJoin = true;
				}
			}
			if($prefJoin){
					array_push($where, '*PREFIX*preferences.configkey = ?');
					array_push($values, 'email');
					$joins .= ' JOIN *PREFIX*preferences ON *PREFIX*users.uid = *PREFIX*preferences.userid';
					$selectMail = ', *PREFIX*preferences.configvalue AS mail ';
			}
			if($groupJoin){
				$joins .= ' JOIN *PREFIX*group_user ON *PREFIX*users.uid = *PREFIX*group_user.uid';
				$selectGroup = ', *PREFIX*group_user.gid AS `group` ';
			}
			if(!empty($where)) $wheres = ' WHERE '.implode(' AND ', $where);
		}
		$sql = "SELECT DISTINCT *PREFIX*users.uid AS user, *PREFIX*users.displayname AS name $selectMail $selectGroup FROM `*PREFIX*users`";
		$sql .= $joins.' '.$wheres;
		if($limit > 0) $sql .= ' LIMIT '.$start.','.$limit.' ';
		$db = OC_DB::prepare($sql);
		$result = $db->execute($values);
		return $result;
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
		return $this->getUsers($filter)->numRows();
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
		$result = $this->getUsers($filter, $start, $limit);
		$ret = array();
		$row = $result->fetchRow();
		while($row){
			$ret[$row['user']]['name'] =$row['name'];
			$ret[$row['user']]['mail'] =$this->getUserMail($row['user']);
			$ret[$row['user']]['grps'] =$this->getUserGroups($row['user']);
			$row = $result->fetchRow();
		}
		return $ret;
	}
	
	
    /**
     * Define a group 
     *
     * @param   string $group
     * @return  bool success
     */
    public function addGroup($group) {
        return OC_Group::createGroup($group);
    }

    
    /**
     * LogOff user
     */
    public function logOff(){
		/* Doesn't work, i don't no why. If I run this 3 lines in an 
		 * external script, it works. Within DokuWiki not */
        $savedSession = session_name();
        session_write_close();
		session_name(OC_Util::getInstanceId());
		session_start();
		OC_User::logout();
        session_write_close();
        session_name($savedSession);
        session_start();
	}
	
	
	/* List all available groups 
	 * 
     * @return array|bool false or array with all groups.
	 */
	public function retrieveGroups($start=0,$limit=-1){
			return OC_Group::getGroups('',$limit,$start);
	}
	
	
	/* List all available groups for a user
	 * 
	 * @param string $user loginname
     * @return array|bool false or array with all groups of this user.
	 */
	private function getUserGroups($user){
		return OC_Group::getUserGroups($user);
	}
	
	/* Get email for a a user
	 * 
	 * @param string $user loginname
     * @return string|bool false or usermail
	 */
	private function getUserMail($user){
		$db = OC_DB::prepare('SELECT `configvalue` FROM `*PREFIX*preferences` WHERE `userid` = ? AND `configkey` = "email"');
		$result = $db->execute(array($user));
		return $result->fetchOne();
	}
}
