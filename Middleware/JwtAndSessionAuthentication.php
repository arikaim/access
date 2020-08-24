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

use Arikaim\Core\Access\Middleware\JwtAuthentication;
use Arikaim\Core\Arikaim;

/**
 * JWT auth middleware
 */
class JwtAndSessionAuthentication extends JwtAuthentication implements MiddlewareInterface
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
        $token = $this->readToken($request);

        if ($token === false) {          
            if (empty(Arikaim::access()->withProvider('session')->getId()) == true) {
                return $this->handleError($request,$handler);
            } 
            return $handler->handle($request);          
        } 

        if ($this->authenticate(['token' => $token]) == false) {
            return $this->handleError($request,$handler);
        };
        
        return $handler->handle($request);
    }    
}
