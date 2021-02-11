<?php
/**
 * Arikaim
 *
 * @link        http://www.arikaim.com
 * @copyright   Copyright (c)  Konstantin Atanasov <info@arikaim.com>
 * @license     http://www.arikaim.com/license
 * 
 */
namespace Arikaim\Core\Access\Provider;

use Arikaim\Core\Access\Interfaces\AuthProviderInterface;
use Arikaim\Core\Access\Provider\AuthProvider;

/**
 * Basic auth provider.
 */
class BasicAuthProvider extends AuthProvider implements AuthProviderInterface
{
    /**
     * Auth user
     *
     * @param array $credentials
     * @return bool
     */
    public function authenticate(array $credentials): bool
    {
        $this->user = $this->getProvider()->getUserByCredentials($credentials);
        if (\is_null($this->user) == true) {
            return false;
        }
      
        return true;             
    }
  
    /**
     * Logout
     *
     * @return void
     */
    public function logout(): void
    {
        $this->user = null;
    }
}
