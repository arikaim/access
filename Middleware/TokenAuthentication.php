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
use Arikaim\Core\Http\Cookie;

/**
 * Token auth middleware
 */
class TokenAuthentication extends AuthMiddleware implements MiddlewareInterface
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

        if ($this->authenticate(['token' => $token]) === false) {   
            echo "handle";          
            return $this->handleError($request,$handler);
        }

        return $handler->handle($request);  
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
