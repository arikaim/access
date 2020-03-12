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
use Arikaim\Core\Db\Model;

/**
 * Token auth provider.
 */
class TokenAuthProvider extends AuthProvider implements AuthProviderInterface
{
    /**
     * Token access type
     */
    const PAGE_ACCESS_TOKEN  = 0;
    const LOGIN_ACCESS_TOKEN = 1;
    const API_ACCESS_TOKEN   = 2;
    const OAUTH_ACCESS_TOKEN = 3;

    /**
     * Authenticate
     *
     * @param array $credentials
     * @return boolean
     */
    public function authenticate(array $credentials)
    {  
        $this->user = $this->getProvider()->getUserByCredentials($credentials);

        return ($this->user !== false);             
    }
  
    /**
     * Logout
     *
     * @return void
     */
    public function logout()
    {   
        $this->user = null;
    }

    /**
     * Create access token
     *
     * @param integer $userId
     * @param integer $type
     * @param integer $expireTime
     * @return array|false
     */
    public function createToken($userId, $type = Self::PAGE_ACCESS_TOKEN, $expireTime = 1800)
    {
        return Model::AccessTokens()->createToken($userId,$type,$expireTime);
    }    
}
