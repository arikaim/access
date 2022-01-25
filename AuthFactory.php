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
    const AUTH_BASIC        = 'basic';
    const AUTH_SESSION      = 'session';
    const AUTH_JWT          = 'jwt';
    const AUTH_TOKEN        = 'token';
    const CSRF_TOKEN        = 'csrf';
    const OAUTH_TOKEN       = 'oauth';
    const AUTH_PUBLIC       = 'public';

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
        Self::AUTH_BASIC,
        Self::AUTH_SESSION,
        Self::AUTH_JWT,
        Self::AUTH_TOKEN,
        Self::CSRF_TOKEN,
        Self::OAUTH_TOKEN,
        Self::AUTH_PUBLIC     
    ];

    /**
     * Auth provider classes
     *
     * @var array
     */
    private static $providerClasses = [      
        Self::AUTH_BASIC   => 'Arikaim\\Core\\Access\\Provider\\BasicAuthProvider',
        Self::AUTH_SESSION => 'Arikaim\\Core\\Access\\Provider\\SessionAuthProvider',
        Self::AUTH_JWT     => 'Arikaim\\Core\\Access\\Provider\\JwtAuthProvider',
        Self::AUTH_TOKEN   => 'Arikaim\\Core\\Access\\Provider\\TokenAuthProvider',
        Self::OAUTH_TOKEN  => 'Arikaim\\Core\\Access\\Provider\\OauthProvider',
        Self::AUTH_PUBLIC  => 'Arikaim\\Core\\Access\\Provider\\PublicAuthProvider'         
    ];

    /**
     * Set user provider
     *
     * @param string $name
     * @param UserProviderInterface $user
     * @return void
     */
    public static function setUserProvider(string $name, UserProviderInterface $user): void
    {
        Self::$userProviders[$name] = $user;
    }

    /**
     * Get user provider
     *
     * @param string $name
     * @return UserProviderInterface|null
     */
    public static function getUserProvider(string $name): ?UserProviderInterface
    {
        return Self::$userProviders[$name] ?? null;
    }

    /**
     * Create auth provider
     *
     * @param string $name
     * @param UserProviderInterface|null $defaultUserProvider
     * @param array $params
     * @return object|null
     */
    public static function createProvider(string $name, ?UserProviderInterface $defaultUserProvider = null, array $params = [])
    {
        if (isset(Self::$providers[$name]) == true) {
            return Self::$providers[$name];
        }
        $class = Self::$providerClasses[$name] ?? ''; 
        if (\class_exists($class) == false) {
            return null;
        }     

        $user = Self::$userProviders[$name] ?? $defaultUserProvider;
        if ($user == null) {
            $user = Self::$userProviders['session'];
        }

        Self::$providers[$name] = new $class($user,$params);
        
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
        $options['authProviders'] = Self::createAuthProviders($authName,$user);

        return (\count($options['authProviders']) == 0) ? null : new AuthMiddleware(null,$options);              
    }
    
    /**
     * Create auth providers
     *
     * @param string|array $authName
     * @param UserProviderInterface|null $user
     * @return array
     */
    public static function createAuthProviders($authName, ?UserProviderInterface $user = null): array
    {
        $providers = (\is_array($authName) == false) ? \explode(',',$authName) : $authName;

        $result = [];
        foreach ($providers as $item) {
            $result[$item] = Self::createProvider($item,$user);
        }

        return $result;
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
     * @param string|null|array $type
     * @return null|string
     */
    public static function resolveAuthType($type): ?string
    {
        if (\is_array($type) == true) {
            return \implode(',',$type);
        }
        if ($type == null) {
            return null;
        }
      
        return \trim((string)$type);
    }

    /**
     * Get auth provider class
     *
     * @param string $name
     * @return string
     */
    public static function getAuthProviderClass(string $name): string
    {
        return Self::$providerClasses[$name] ?? '';
    }
}
