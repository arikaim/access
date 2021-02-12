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

use Psr\Http\Message\ServerRequestInterface;

use Arikaim\Core\Access\Interfaces\AuthProviderInterface;
use Arikaim\Core\Access\Provider\AuthProvider;
use Arikaim\Core\Db\Model;
use Arikaim\Core\Http\Cookie;

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
     * @param ServerRequestInterface|null $request
     * @return boolean
     */
    public function authenticate(array $credentials, ?ServerRequestInterface $request = null): bool
    {   
        $token = $credentials['token'] ?? null;
        if (empty($token) == true) {
            $credentials['token'] = $this->readToken($request);
        }       
       
        $this->user = $this->getProvider()->getUserByCredentials($credentials);
    
        return (\is_null($this->user) == true) ? false : true;             
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

    /**
     * Create access token
     *
     * @param integer $userId
     * @param integer $type
     * @param integer $expireTime
     * @return array|false
     */
    public function createToken($userId, int $type = Self::PAGE_ACCESS_TOKEN, int $expireTime = 1800)
    {
        return Model::AccessTokens()->createToken($userId,$type,$expireTime);
    }   
    
    /**
     * Get token from request header or cookies
     *
     * @param ServerRequestInterface $request
     * @return string|null
    */
    protected function readToken(ServerRequestInterface $request): ?string
    {   
        $route = $request->getAttribute('route');
        $token = $route->getArgument('token'); 
      
        if (empty($token) == true) {
            // try from requets body 
            $vars = $request->getParsedBody();
            $token = $vars['token'] ?? null;             
        }     

        if (empty($token) == true) {      
            $token = Cookie::get('token',$request);
        }
        
        return $token;
    }
}
