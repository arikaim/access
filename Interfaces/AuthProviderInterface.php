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
 * Auth provider interface
 */
interface AuthProviderInterface
{    
    /**
     * Logout
     *
     * @return void
     */
    public function logout(): void;

    /**
     * Get current auth user
     *
     * @return array|null
     */
    public function getUser();
    
    /**
     * Get current auth id
     *
     * @return integer|null
     */
    public function getId();

    /**
     * Authenticate user 
     *
     * @param array $credentials
     * @return bool
     */
    public function authenticate(array $credentials): bool;

    /**
     * Get login attempts
     *
     * @return integer|null
     */
    public function getLoginAttempts(): ?int;
}
