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
    const AUTH_JWT_SESSION  = 7;

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
        'oauth',
        'jwt-session'
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
        'OauthProvider',
        'JwtAuthProvider'
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
        'CsrfToken',
        null,
        'JwtAndSessionAuthentication'
    ];

    /**
     * Create auth provider
     *
     * @param string $name
     * @param UserProviderInterface $user
     * @param array $params
     * @return object|null
     */
    public static function createProvider($name, UserProviderInterface $user, array $params = [])
    {
        $className = (\class_exists($name) == true) ? $name : Self::getAuthProviderClass(Self::resolveAuthType($name));
        $fullClassName = Self::ACCESS_NAMESPACE . 'Provider\\' . $className;
    
        return (\class_exists($fullClassName) == true) ? new $fullClassName($user,$params) : null;
    }

    /**
     * Create auth middleware
     *
     * @param string $authName   
     * @param UserProviderInterface $user
     * @param array $options
     * @return object|null
     */
    public static function createMiddleware($authName, UserProviderInterface $user, $options = [])
    {       
        $className = (\class_exists($authName) == true) ? $authName : Self::getAuthMiddlewareClass(Self::resolveAuthType($authName));
        $fullClassName = Self::ACCESS_NAMESPACE . 'Middleware\\' . $className;
      
        $provider = Self::createProvider($authName,$user);
       
        return (\class_exists($fullClassName) == true) ? new $fullClassName($provider,$options) : null;
    }

    /**
     * Return auth type id
     *
     * @param string $name
     * @return int
     */
    public static function getTypeId($name)
    {
        return \array_search($name,Self::$authNames);                 
    }

    /**
     * Check if auth name is valid 
     *
     * @param string $name
     * @return boolean
     */
    public static function isValidAuthName($name)
    {
        return (\array_search($name,Self::$authNames) === false) ? false : true;     
    }

    /**
     * Resolve auth type
     *
     * @param string|integer $type
     * @return null|integer
     */
    public static function resolveAuthType($type)
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
     * @return string
     */
    public static function getAuthName($auth)
    {
        return Self::$authNames[$auth] ?? false;          
    }

    /**
     * Get middleware class name
     *
     * @param integer $id
     * @return string
     */
    public static function getAuthMiddlewareClass($id)
    {     
        return Self::$middlewareClasses[$id] ?? '';
    }

    /**
     * Get auth provider class
     *
     * @param integer $id
     * @return string|false
     */
    public static function getAuthProviderClass($id)
    {
        return Self::$providerClasses[$id] ?? '';
    }
}
