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
 * Session auth provider.
 */
class SessionAuthProvider extends AuthProvider implements AuthProviderInterface
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
            // fail to auth
            $loginAttempts = $this->getLoginAttempts() + 1;
            Session::set('auth.login.attempts',$loginAttempts);
            // not vlaid user
            return false;
        }
        // success
        Session::set('auth.id',$this->user['auth_id'] ?? null);
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
     * Get current auth user
     *
     * @return array|null
    */
    public function getUser()
    {
        $authId = $this->getId();
        
        return (empty($authId) == true) ? null : $this->getProvider()->getUserById($authId);
    }

    /**
     * Gte auth id
     *
     * @return null|integer
     */
    public function getId()
    {
        return (int)Session::get('auth.id',null);     
    }

    /**
     * Get login attempts 
     *
     * @return integer
     */
    public function getLoginAttempts(): ?int
    {
        return (int)Session::get('auth.login.attempts',0);  
    }
}
