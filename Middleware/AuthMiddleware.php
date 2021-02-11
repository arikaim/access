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

use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpNotFoundException;

use Arikaim\Core\Access\Interfaces\AuthProviderInterface;
use Arikaim\Core\Http\Response;
use Arikaim\Core\Arikaim;

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
    public function __construct(AuthProviderInterface $auth, array $options = [])
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
    protected function authenticate(array $credentials): bool
    {
        $result = ($this->getAuthProvider()->authenticate($credentials) == true); 
        if ($result == true) {
            Arikaim::get('access')->setProvider($this->getAuthProvider());
        }

        return $result;
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
     * @throws HttpNotFoundException
     */
    protected function handleError($request, $handler)
    {      
        $redirect = $this->options['redirect'] ?? false;
        $response = Response::create();

        if (empty($redirect) == false) { 
            // redirect         
            return $response
                ->withoutHeader('Cache-Control')
                ->withHeader('Cache-Control','no-cache, must-revalidate')
                ->withHeader('Content-Length','0')    
                ->withHeader('Expires','Sat, 26 Jul 1997 05:00:00 GMT')        
                ->withHeader('Location',$redirect)
                ->withStatus(307);                 
        }

        throw new HttpNotFoundException($request);
        
        return $response->withStatus(401); 
    }

    /**
     * Get option value
     *
     * @param string $key
     * @param mixed|null $default
     * @return mixed
     */
    protected function getOption(string $key, $default = null)
    {
        return $this->options[$key] ?? $default;
    }
}
