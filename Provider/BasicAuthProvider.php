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

/**
 * Basic auth provider.
 */
class BasicAuthProvider extends AuthProvider implements AuthProviderInterface
{
    /**
     * Auth user
     *
     * @param array $credentials
     * @param ServerRequestInterface|null $request
     * @return bool
     */
    public function authenticate(array $credentials, ?ServerRequestInterface $request = null): bool
    {
        $credentials = $this->getCredentials($request);
        
        $this->user = $this->getProvider()->getUserByCredentials($credentials);
        if (\is_null($this->user) == true) {
            return false;
        }
      
        return true;             
    }
  
     /**
     * Get basic http auth credentials
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @return array
     */
    protected function getCredentials($request): array
    {
        return [
            'user_name' => $request->getHeader('PHP_AUTH_USER'),
            'password'  => $request->getHeader('PHP_AUTH_PW')
        ];
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
