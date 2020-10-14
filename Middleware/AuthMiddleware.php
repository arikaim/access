<?php
/**
 * Arikaim
 *
 * @link        http://www.arikaim.com
 * @copyright   Copyright (c)  Konstantin Atanasov <info@arikaim.com>
 * @license     http://www.arikaim.com/license
 * 
*/
namespace Arikaim\Core\Access\Middleware;

use Arikaim\Core\Access\Interfaces\AuthProviderInterface;
use Arikaim\Core\Http\Response;

/**
 *  Middleware base class
 */
class AuthMiddleware
{
    /**
     * Auth provider
     *
     * @var AuthProviderInterface
     */
    protected $auth;

    /**
     * Options
     *
     * @var array
     */
    protected $options;

    /**
     * Constructor
     *
     * @param AuthProviderInterface $auth
     * @param array $options
     */
    public function __construct(AuthProviderInterface $auth, $options = [])
    {
        $this->auth = $auth;     
        $this->options = $options;
    }
    
    /**
     * Authenticate
     *
     * @param array $credentials
     * @return boolean
     */
    protected function authenticate(array $credentials)
    {
        return ($this->getAuthProvider()->authenticate($credentials) == true);                   
    }

    /**
     * Get auth provider
     *
     * @return AuthProviderInterface
     */
    public function getAuthProvider()
    {
        return $this->auth;
    }

    /**
     * Show auth error
     *
     * @param ServerRequestInterface  $request
     * @param RequestHandlerInterface $handler
     * @return string
     */
    protected function handleError($request, $handler)
    {      
        $redirect = (isset($this->options['redirect']) == true) ? $this->options['redirect'] : null;
    
        if (empty($redirect) == false) {
            $response = $handler->handle($request);
            return $response->withHeader('Location',$redirect)->withStatus(302);                   
        }

        $response = Response::create();
    
        return $response->withStatus(401); 
    }

    /**
     * Get option value
     *
     * @param string $key
     * @param mixed|null $default
     * @return mixed
     */
    protected function getOption($key, $default = null)
    {
        return (isset($this->options[$key]) == true) ? $this->options[$key] : $default;
    }
}
