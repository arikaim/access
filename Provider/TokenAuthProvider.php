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
use Arikaim\Core\Http\Cookie;

/**
 * Token auth provider.
 */
class TokenAuthProvider extends AuthProvider implements AuthProviderInterface
{
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
     * Get token from request header or cookies
     *
     * @param ServerRequestInterface $request
     * @return string|null
    */
    protected function readToken(ServerRequestInterface $request): ?string
    {   
        // from request header
        $token = AuthProvider::readAuthHeader($request,false);
        if (empty($token) == false) {
            return $token;
        }

        // from route
        $route = $request->getAttribute('route');
        $token = $route->getArgument('token'); 
      
        // from request body
        if (empty($token) == true) {
            // try from requets body 
            $vars = $request->getParsedBody();
            $token = $vars['token'] ?? null;             
        }     

        // from cookie
        if (empty($token) == true) {      
            $token = Cookie::get('token',$request);
        }
        
        return $token;
    }
}
