<?php defined('SYSPATH') or die('No direct script access.');
/**
 * Trait for Model_User that enables DB based ACL functionality.
 * Use this as a PHP 5.4 trait in APPPATH.'classes/model/user.php'
 *
 * @since 1.0
 * @author Ando Roots <ando@sqroot.eu>
 */
trait ACL_Trait_User
{
	/**
	 * Check if the user has the specified permission.
	 *
	 * @since 1.0
	 * @param int|ACL_Model_Permission $permission
	 * @return bool
	 */
	public function can($permission)
	{
		return $this->_check_permission($permission);
	}

	/**
	 * Check if the user has all the specified permissions.
	 *
	 * @since 1.0
	 * @param array $permissions An array of ACL_Model_Permission or Permission PK-s
	 * @return bool True if the user has all the specified permissions
	 */
	public function has_permissions(array $permissions)
	{
		foreach ($permissions as $permission) {
			if (! $this->_check_permission($permission)) {
				return FALSE;
			}
		}
		return TRUE;
	}

	/**
	 * Check if the user has at least one of the specified permissions.
	 * @since 1.0
	 * @param array $permissions An array of ACL_Model_Permission or Permission PK-s
	 * @return bool True if the user had one of the permissions
	 */
	public function has_any_permission(array $permissions)
	{
		foreach ($permissions as $permission) {
			if ($this->_check_permission($permission)) {
				return TRUE;
			}
		}
		return FALSE;
	}

	/**
	 * Check if a user has the specified permissions.
	 *
	 * @param array|string $permission
	 * @throws InvalidArgumentException
	 * @see Model_Permission
	 * @return bool
	 * @since 2.0
	 */
	private function _check_permission($permission)
	{
		// Todo: Do this with one DB::select query
		foreach ($this->roles->find_all() as $role) {
			if(is_array($permission)){
				foreach($permission as $checked){
					if($role->can($checked))
						return TRUE;
				}
			} elseif ($role->can($permission)) {
				return TRUE;
			}
		}
		return FALSE;
	}
}