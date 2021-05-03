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
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Slim\Exception\HttpNotFoundException;

use Arikaim\Core\Access\Interfaces\AuthProviderInterface;
use Arikaim\Core\Http\Response;
use Arikaim\Core\Arikaim;

/**
 *  Middleware base class
 */
class AuthMiddleware implements MiddlewareInterface
{
    /**
     * Auth provider
     *
     * @var array
     */
    protected $authProviders;

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
    public function __construct(array $authProviders, array $options = [])
    {
        $this->authProviders = $authProviders;     
        $this->options = $options;
    }
    
    /**
     * Process middleware
     * 
     * @param ServerRequestInterface  $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
    */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {      
        foreach ($this->authProviders as $name => $provider) {

            if ($provider->isLogged() == true) {
                Arikaim::get('access')->withProvider($provider);     

                return $handler->handle($request);  
            }
            
            if ($provider->authenticate([],$request) == true) {
                // success
                Arikaim::get('access')->withProvider($provider);     

                return $handler->handle($request);  
            } 
        }
        
        // error
        return $this->handleError($request,$handler);
    }

    /**
     * Get auth provider
     *
     * @return AuthProviderInterface|null
     */
    public function getAuthProvider($name)
    {
        return $this->authProviders[$name] ?? null;
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
