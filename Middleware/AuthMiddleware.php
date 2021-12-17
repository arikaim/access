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
use Psr\Http\Message\ResponseInterface;

use Arikaim\Core\Framework\Middleware\Middleware;
use Arikaim\Core\Framework\MiddlewareInterface;
use Arikaim\Core\Access\Interfaces\AuthProviderInterface;
use Arikaim\Core\Arikaim;
use Arikaim\Core\Access\AccessDeniedException;

/**
 *  Auth Middleware base class
 */
class AuthMiddleware extends Middleware implements MiddlewareInterface
{
    /**
     * Auth provider
     *
     * @var array
     */
    protected $authProviders;

    /**
     * Constructor
     *
     * @param ContainerInterface|null
     * @param array|null $options
     */
    public function __construct($container = null, ?array $options = [])
    {
       parent::__construct($container,$options);
       $this->authProviders = $options['authProviders'] ?? [];  
    }

    /**
     * Set Auth providers
     *
     * @param array $authProviders
     * @return void
     */
    public function setAuthProviders(array $authProviders): void
    {
        $this->authProviders = $authProviders; 
    }

    /**
     * Process middleware
     * 
     * @param ServerRequestInterface  $request  
     * @return ResponseInterface
    */
    public function process(ServerRequestInterface $request, ResponseInterface $response): array
    {      
        foreach ($this->authProviders as $provider) {

            if ($provider->isLogged() == true) {
                Arikaim::get('access')->withProvider($provider);     
                return [$request,$response];
            }
            
            if ($provider->authenticate([],$request) == true) {
                // success
                Arikaim::get('access')->withProvider($provider);     
                return [$request,$response];
            } 
        }
             
        return [$request,$this->handleError($response)];
    }

    /**
     * Get auth provider
     *
     * @return AuthProviderInterface|null
     */
    public function getAuthProvider($name): ?AuthProviderInterface
    {
        return $this->authProviders[$name] ?? null;
    }

    /**
     * Show auth error
     *
     * @param ResponseInterface $response
     * @return ResponseInterface
     * @throws AccessDeniedException
     */
    protected function handleError($response): ResponseInterface
    {      
        $redirect = $this->options['redirect'] ?? false;

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

        $response->withStatus(401);
        throw new AccessDeniedException('Access Denied');
        
        return $response; 
    }    
}
