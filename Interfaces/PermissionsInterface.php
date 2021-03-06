<?php
/**
 * Arikaim
 *
 * @link        http://www.arikaim.com
 * @copyright   Copyright (c)  Konstantin Atanasov <info@arikaim.com>
 * @license     http://www.arikaim.com/license
 * 
*/
namespace Arikaim\Core\Access\Interfaces;

/**
 * Permissions interface
 */
interface PermissionsInterface
{    
    /**
     * Get user permission
     *
     * @param string|int $name
     * @param mixed $userId
     * @param array $permissions
     * @return boolean
     */
    public function hasPermissions($name, $userId, array $permissions): bool;

    /**
     * Add permission item.
     *
     * @param string $name    
     * @param string|null $title
     * @param string|null $description
     * @param string|null $extension
     * @return boolean
     */
    public function addPermission(string $name, ?string $title = null, ?string $description = null, ?string $extension = null): bool;

    /**
     * Get user permissions list
     *
     * @param integer $authId
     * @return mixed
    */
    public function getUserPermissions($authId);
}
