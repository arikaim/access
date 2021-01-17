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
use Arikaim\Core\Http\Session;
use Arikaim\Core\Access\Provider\AuthProvider;

/**
 * OAuth provider.
 */
class OauthProvider extends AuthProvider implements AuthProviderInterface
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
        
        if ($this->user === false) {
            $loginAttempts = $this->getLoginAttempts() + 1;       
            Session::set('auth.login.attempts',$loginAttempts);
            
            return false;
        }
      
        Session::set('auth.id',$this->user->getAuthId());
        Session::set('auth.login.time',time());
        Session::remove('auth.login.attempts');              
        
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
        Session::remove('auth.id');
        Session::remove('auth.login.time');
        Session::remove('auth.login.attempts');  
    }

    /**
     * Gte auth id
     *
     * @return null|integer
     */
    public function getId()
    {
        return Session::get('auth.id',null);     
    }

    /**
     * Get current auth user
     *
     * @return UserProviderInterface
     */
    public function getUser()
    {
        return (empty($this->getId()) == true) ? null : $this->userProvider->getUserById($this->getId());
    }

    /**
     * Get login attempts 
     *
     * @return integer
     */
    public function getLoginAttempts(): ?int
    {
        return (integer)Session::get('auth.login.attempts',0);  
    }
}
