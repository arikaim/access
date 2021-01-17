<?php
/**
 * Arikaim
 *
 * @link        http://www.arikaim.com
 * @copyright   Copyright (c)  Konstantin Atanasov <info@arikaim.com>
 * @license     http://www.arikaim.com/license
 * 
 */
namespace Arikaim\Core\Access;

use Arikaim\Core\Access\Interfaces\UserProviderInterface;

/**
 * Auth factory class.
 */
class AuthFactory
{
    const ACCESS_NAMESPACE = 'Arikaim\\Core\\Access\\';
   
    // auth type id
    const AUTH_BASIC        = 1;
    const AUTH_SESSION      = 2;
    const AUTH_JWT          = 3;
    const AUTH_TOKEN        = 4;
    const CSRF_TOKEN        = 5;
    const OAUTH_TOKEN       = 6;

    /**
     * Providers object pool
     *
     * @var array
     */
    private static $providers;

    /**
     * Middleware object pool
     *
     * @var array
     */
    private static $middleware;

    /**
     * Auth name
     *
     * @var array
     */
    private static $authNames = [
        'none',
        'basic',
        'session',
        'jwt',
        'token',
        'csrf',
        'oauth'
    ];

    /**
     * Auth provider classes
     *
     * @var array
     */
    private static $providerClasses = [
        null,
        'BasicAuthProvider',
        'SessionAuthProvider',
        'JwtAuthProvider',
        'TokenAuthProvider',
        null,
        'OauthProvider'
    ];

    /**
     * Auth Middleware classes
     *
     * @var array
     */
    private static $middlewareClasses = [
        null,
        'BasicAuthentication',
        'SessionAuthentication',
        'JwtAuthentication',
        'TokenAuthentication',
        'CsrfToken'
    ];

    /**
     * Create auth provider
     *
     * @param string|integer $name
     * @param UserProviderInterface $user
     * @param array $params
     * @return object|null
     */
    public static function createProvider($name, UserProviderInterface $user, array $params = [])
    {
        if (isset(Self::$providers[$name]) == true) {
            return Self::$providers[$name];
        }
        $className = (\class_exists($name) == true) ? $name : Self::getAuthProviderClass(Self::resolveAuthType($name));
        $fullClassName = Self::ACCESS_NAMESPACE . 'Provider\\' . $className;
    
        Self::$providers[$name] = (\class_exists($fullClassName) == true) ? new $fullClassName($user,$params) : null;
        
        return Self::$providers[$name];
    }

    /**
     * Create auth middleware
     *
     * @param string|integer $authName   
     * @param UserProviderInterface $user
     * @param array $options
     * @return object|null
     */
    public static function createMiddleware($authName, UserProviderInterface $user, array $options = [])
    {       
        if (isset(Self::$middleware[$authName]) == true) {
            return Self::$middleware[$authName];
        }

        $className = (\class_exists($authName) == true) ? $authName : Self::getAuthMiddlewareClass(Self::resolveAuthType($authName));
        $fullClassName = Self::ACCESS_NAMESPACE . 'Middleware\\' . $className;
      
        $provider = Self::createProvider($authName,$user);
        Self::$middleware[$authName] = (\class_exists($fullClassName) == true) ? new $fullClassName($provider,$options) : null;

        return Self::$middleware[$authName];
    }

    /**
     * Return auth type id
     *
     * @param string $name
     * @return int
     */
    public static function getTypeId(string $name): int
    {
        return (int)\array_search($name,Self::$authNames);                 
    }

    /**
     * Check if auth name is valid 
     *
     * @param string $name
     * @return boolean
     */
    public static function isValidAuthName(string $name): bool
    {
        return (\array_search($name,Self::$authNames) !== false);
    }

    /**
     * Resolve auth type
     *
     * @param string|integer $type
     * @return null|integer
     */
    public static function resolveAuthType($type): ?int
    {
        if (\is_string($type) == true) {           
            return Self::getTypeId($type);
        }

        return (\is_integer($type) == true) ? $type : null;
    }

    /**
     * Return auth name
     *
     * @param int $auth
     * @return string|null
     */
    public static function getAuthName($auth): ?string
    {
        return Self::$authNames[$auth] ?? null;          
    }

    /**
     * Get middleware class name
     *
     * @param integer $id
     * @return string
     */
    public static function getAuthMiddlewareClass($id): string
    {     
        return Self::$middlewareClasses[$id] ?? '';
    }

    /**
     * Get auth provider class
     *
     * @param integer $id
     * @return string
     */
    public static function getAuthProviderClass($id): string
    {
        return Self::$providerClasses[$id] ?? '';
    }
}
