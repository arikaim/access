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

use Arikaim\Core\Interfaces\SystemErrorInterface;
use Arikaim\Core\Access\Interfaces\AuthProviderInterface;

use Arikaim\Core\Arikaim;

/**
 *  Middleware base class
 */
class AuthMiddleware
{
    /**
     * Auth provider
     *
     * @var Arikaim\Core\Access\Interfaces\AuthProviderInterface
     */
    protected $auth;

    /**
     * System error renderer
     *
     * @var SystemErrorInterface
     */
    protected $errorRenderer;

    /**
     * Options
     *
     * @var array
     */
    protected $options;

    /**
     * Constructor
     *
     * @param SystemErrorInterface $errorRenderer
     * @param array $options
     */
    public function __construct(AuthProviderInterface $auth, SystemErrorInterface $errorRenderer, $options = [])
    {
        $this->auth = $auth;
        $this->errorRenderer = $errorRenderer;
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
        if ($this->getAuthProvider()->authenticate($credentials) == true) {
            Arikaim::access()->setProvider($this->getAuthProvider());
            return true;
        }

        return false;
    }

    /**
     * Get auth provider
     *
     * @return Arikaim\Core\Access\Interfaces\AuthProviderInterface
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

        $this->errorRenderer->renderSystemErrors($request,'AUTH_FAILED'); 
        exit();      
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
