<?php defined('SYSPATH') or die('No direct script access.');
/**
 * @since 1.0
 * @author Ando Roots <ando@roots.ee>
 */
class ACL_Model_Role extends Model_Auth_Role
{
	// Basic Role constants
	const LOGIN = 1; // Allow login
	const ADMIN = 1000; // Never-ever give this role to daily system users! Only for developers.

	protected $_has_many = array(
		'permissions' => array('through' => 'permissions_roles'),
		'users'       => array('through' => 'roles_users')
	);

	/**
	 * Check whether the current role can do some action.
	 *
	 * @since 1.0
	 * @param int $permission Either an instance of ACL_Model_Permission or a numeric Permission ID
	 * @return bool True if the action is authorized for this role
	 */
	public function can($permission)
	{	
		//login check
		if (!Auth::instance()->logged_in()) {
			return false;
		}
		
		//filter our argument  type
		if(is_string($permission)){
			$permission=ORM::factory('Permission')->where('name','=',$permission)->find();
		} elseif (is_numeric($permission)){
			$permission=ORM::factory('Permission',$permission);
		}
		//if not loaded
		if (! $permission instanceof ACL_Model_Permission && $permission->loaded()) {
			throw new InvalidArgumentException('Expected an instance of ACL_Model_Permission');
		}
		
		// The ADMIN role is all-powerful
		if (Auth::instance()->get_user()->roles->find()->pk() == self::ADMIN) {
			return true;
		}
		
		foreach(Auth::instance()->get_user()->roles->find_all() as $role){
			if($role->has('permissions',$permission))
				return true;
		}
		return false;
	}
}
