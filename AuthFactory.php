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
use Arikaim\Core\Access\Middleware\AuthMiddleware;

/**
 * Auth factory class.
 */
class AuthFactory
{
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
    private static $providers = [];

    /**
     * User providers
     *
     * @var array
     */
    private static $userProviders = [];

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
     * Set user provider
     *
     * @param string $authName
     * @param UserProviderInterface $user
     * @return void
     */
    public static function setUserProvider(string $authName, UserProviderInterface $user): void
    {
        Self::$userProviders[$authName] = $user;
    }

    /**
     * Get user provider
     *
     * @param string $authName
     * @return UserProviderInterface|null
     */
    public static function getUSerProvider(string $authName): ?UserProviderInterface
    {
        return Self::$userProviders[$authName] ?? null;
    }

    /**
     * Create auth provider
     *
     * @param string|integer $name
     * @param UserProviderInterface|null $defaultUserProvider
     * @param array $params
     * @return object|null
     */
    public static function createProvider($name, ?UserProviderInterface $defaultUserProvider = null, array $params = [])
    {
        if (isset(Self::$providers[$name]) == true) {
            return Self::$providers[$name];
        }
        $className = (\class_exists($name) == true) ? $name : Self::getAuthProviderClass(Self::resolveAuthType($name));
        $fullClassName = 'Arikaim\\Core\\Access\\Provider\\' . $className;
        $user = Self::$userProviders[$name] ?? $defaultUserProvider ?? Self::$userProviders['session'];

        Self::$providers[$name] = (\class_exists($fullClassName) == true) ? new $fullClassName($user,$params) : null;
        
        return Self::$providers[$name];
    }

    /**
     * Create auth middleware
     *
     * @param string $authName   
     * @param UserProviderInterface|null $user
     * @param array $options
     * @return object|null
     */
    public static function createMiddleware(string $authName, ?UserProviderInterface $user = null, array $options = [])
    {       
        $tokens = \explode(',',$authName);
        $providers = [];
        foreach ($tokens as $item) {
            $name = (\is_numeric($item) == true) ? Self::getAuthName($item) : $item; 
            $providers[$name] = Self::createProvider($name,$user);
        }
    
        return (\count($providers) == 0) ? null : new AuthMiddleware($providers,$options);              
    }

    /**
     * Create auth providers
     *
     * @param string|array $authName
     * @return array
     */
    public static function createAuthProviders($authName): array
    {
        $providers = (\is_array($authName) == false) ? \explode(',',$authName) : $authName;

        $result = [];
        foreach ($providers as $item) {
            $name = (\is_numeric($item) == true) ? Self::getAuthName($item) : $item; 
            $result[$name] = Self::createProvider($item,null);
        }

        return $result;
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
     * @param string|integer|array $type
     * @return null|integer|string
     */
    public static function resolveAuthType($type)
    {
        if (\is_numeric($type) == true) {
            return (int)$type;
        }
        if (\is_string($type) == true) {           
            return Self::getTypeId($type);
        }
        if (\is_array($type) == true) {
            $result = '';
            foreach($type as $item) {
                $id = Self::getTypeId($item);
                $result .= (empty($result) == false) ? ',' . $id : $id;
            }

            return $result;
        }

        return null;
    }

    /**
     * Return auth name
     *
     * @param int $auth
     * @return string|null
     */
    public static function getAuthName(int $auth): ?string
    {
        return Self::$authNames[$auth] ?? null;          
    }

    /**
     * Get auth provider class
     *
     * @param integer|string $id
     * @return string
     */
    public static function getAuthProviderClass($id): string
    {
        return Self::$providerClasses[$id] ?? '';
    }
}
