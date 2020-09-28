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

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use Arikaim\Core\Access\Middleware\AuthMiddleware;

/**
 * Basic HTTP auth middleware
 */
class BasicAuthentication extends AuthMiddleware implements MiddlewareInterface
{
    /**
     * Process middleware
     * 
     * @param ServerRequestInterface  $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
    */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {      
        if (empty($this->getAuthProvider()->getId()) == false) {
            return $handler->handle($request);
        }
        // auth
        $credentials = $this->getCredentials($request);

        if ($this->authenticate($credentials) == false) {            
            return $this->handleError($request,$handler);          
        }

        return $handler->handle($request);
    }

    /**
     * Get basic http auth credentials
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @return array
     */
    protected function getCredentials($request)
    {
        return [
            'user_name' => $request->getHeader('PHP_AUTH_USER'),
            'password'  => $request->getHeader('PHP_AUTH_PW')
        ];
    }
}
