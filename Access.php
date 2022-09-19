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

use Arikaim\Core\Interfaces\Access\AccessInterface;
use Arikaim\Core\Access\Interfaces\PermissionsInterface;
use Arikaim\Core\Access\Interfaces\UserProviderInterface;
use Arikaim\Core\Access\Interfaces\AuthProviderInterface;
use Arikaim\Core\Access\AuthFactory;
use Arikaim\Core\Access\Provider\SessionAuthProvider;

/**
 * Manage permissions.
 */
class Access implements AccessInterface
{ 
    const DEFAULT_AUTH_PROVIDER = 'session';

    /**
     * Permissions adapter
     *
     * @var PermissionsInterface
     */
    private $adapter;

    /**
     * Auth user
     *
     * @var UserProviderInterface
    */
    private $user;

    /**
     * Undocumented variable
     *
     * @var AuthProviderInterface
     */
    private $provider = null;

    /**
     * Auth provider options
     *
     * @var array
     */
    private $providerOptions = [];

    /**
     * Constructor
     * 
     * @param PermissionsInterface $adapter
    */
    public function __construct(
        PermissionsInterface $adapter, 
        UserProviderInterface $user, 
        ?AuthProviderInterface $provider = null,
        array $providerOptions = [] 
    ) 
    {
        $this->adapter = $adapter;  
        $this->user = $user;
        $this->provider = $provider ?? new SessionAuthProvider($user); 
        $this->providerOptions = $providerOptions;
    }

    /**
     * Auth user 
     *
     * @param array $credentials
     * @return bool
     */
    public function authenticate(array $credentials): bool
    {
        return $this->provider->authenticate($credentials);
    }

    /**
     * Create auth middleware
     *
     * @param string $authName
     * @param array $options
     * @param UserProviderInterface|null $user
     * @return object|null
     */
    public function middleware(string $authName, array $options = [], ?UserProviderInterface $user = null)
    {       
        return AuthFactory::createMiddleware(
            $authName,
            $user ?? $this->user,
            $options
        );       
    }

    /**
     * Change auth provider
     *
     * @param AuthProviderInterface|string $provider
     * @param UserProviderInterface|null $user
     * @param array $params
     * @return AuthProviderInterface
     */
    public function withProvider($provider, $user = null, array $params = [])
    {
        $provider = ($provider instanceof AuthProviderInterface) ? $provider : $this->createProvider($provider,$user,$params);
        $this->setProvider($provider);

        return $provider;
    }

    /**
     * Create auth provider
     *
     * @param string $name
     * @param UserProviderInterface|null $user
     * @param array|null $params
     * @return object|null
     */
    public function createProvider(string $name, ?UserProviderInterface $user = null, ?array $params = null)
    { 
        return AuthFactory::createProvider(
            $name,
            $user ?? $this->user,
            $params ?? $this->providerOptions
        );       
    }

    /**
     * Set auth provider
     *
     * @param AuthProviderInterface $provider
     * @return void
     */
    public function setProvider(AuthProviderInterface $provider)
    {
        $this->provider = $provider;
    }

    /**
     * Return auth provider
     *
     * @return AuthProviderInterface|null
     */
    public function getProvider()
    {
        return $this->provider;
    }

    /**
     * Full Permissions 
     *
     * @return array
     */
    public function getFullPermissions(): array
    {
        return AccessInterface::FULL;
    }

    /**
     * Control panel permission name
     *
     * @return string
     */
    public function getControlPanelPermission(): string
    {
        return AccessInterface::CONTROL_PANEL;
    }

    /**
     * Set permissions adapter
     *
     * @param PermissionsInterface $adapter
     * @return void
     */
    public function setAdapter(PermissionsInterface $adapter): void
    {
        $this->adapter = $adapter;
    }

    /**
     * Get permissions adapter
     *
     * @return PermissionsInterface
     */
    public function getAdapter()
    {        
        return $this->adapter;
    }
    
    /**
     * Check if current loged user have control panel access
     *
     * @param string|integer|null $authId
     * @return boolean
     */
    public function hasControlPanelAccess($authId = null): bool
    {
        $authId = (empty($authId) == true) ? $this->getId() : $authId;
      
        return (empty($authId) == true) ? false : $this->hasAccess(AccessInterface::CONTROL_PANEL,AccessInterface::FULL,$authId);
    }
    
    /**
     * Return true if user has one permission from permissions list
     *
     * @param array  $names Permission names
     * @param string|array|null $type PermissionType (read,write,execute,delete)   
     * @param string|integer|null $authId 
     * @return boolean
     */
    public function hasAccessOneFrom(array $names, $type = null, $authId = null): bool 
    {
        foreach($names as $name) {
            if ($this->hasAccess($name,$type,$authId) == true) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check access 
     *
     * @param string|int $name Permission name
     * @param string|array|null $type PermissionType (read,write,execute,delete)   
     * @param string|integer|null $authId 
     * @return boolean
     */
    public function hasAccess($name, $type = null, $authId = null): bool
    {       
        list($name,$permissionType) = $this->resolvePermissionName($name);
        if (\is_array($permissionType) == false) {           
            $permissionType = $this->resolvePermissionType($type);
        }
        
        return $this->adapter->hasPermissions(
            $name,
            $authId ?? $this->getId(),
            $permissionType
        );            
    }

    /**
     * Check for deny permission 
     *
     * @param string|int $name Permission name
     * @param string|array|null $type PermissionType (read,write,execute,delete)   
     * @param string|integer|null $authId 
     * @return boolean
     */
    public function hasDeny($name, $type = null, $authId = null): bool
    {      
        list($name,$permissionType) = $this->resolvePermissionName($name);  
        if (\is_array($permissionType) == false) {           
            $permissionType = $this->resolvePermissionType($type);
        }

        return $this->adapter->hasPermissions(
            $name,
            $authId ?? $this->getId(),
            $permissionType,
            true
        );    
    }

    /**
     * Get user permissions
     *
     * @param integer|null $authId
     * @return mixed
     */
    public function getUserPermissions(?int $authId = null)
    {
        return $this->adapter->getUserPermissions($authId ?? $this->getId());
    }

    /**
     * Add permission item.
     *
     * @param string $name    
     * @param string|null $title
     * @param string|null $description
     * @param string|null $extension
     * @param bool|null $deny
     * @return boolean
     */
    public function addPermission(
        string $name, 
        ?string $title = null, 
        ?string $description = null, 
        ?string $extension = null,
        ?bool $deny = false
    ): bool
    {
        return $this->adapter->addPermission($name,$title,$description,$extension,$deny);
    }

    /**
     * Resolve permission full name  name:type
     *
     * @param string $name
     * @return array
     */
    public function resolvePermissionName(string $name): array
    {
        $tokens = \explode(':',$name);
        $name = $tokens[0];
        $type = $tokens[1] ?? null;     

        if (empty($type) == false) {
            $type = (\strtolower($type) == 'full') ? AccessInterface::FULL : \explode(',',$type);
        }
        
        return [
            $name,
            $type
        ];
    }

    /**
     * Resolve permission type
     *
     * @param string|array $type
     * @return array
     */
    protected function resolvePermissionType($type): array
    {
        if (\is_string($type) == true) {
            $type = \explode(',',$type); 
        }

        if (\is_array($type) == false) {
            return AccessInterface::FULL;
        }

        return (empty($type) == true) ? AccessInterface::FULL : $type;          
    }

    /**
     * Logout
     *
     * @return void
     */
    public function logout(): void
    {
        $this->provider->logout();
    }

    /**
     * Get logged user
     *
     * @return array|null
     */
    public function getUser(): ?array
    {
        return $this->provider->getUser();
    }

    /**
     * Get login attempts
     *
     * @return null|integer
     */
    public function getLoginAttempts(): ?int
    {
        return $this->provider->getLoginAttempts();
    }

    /**
     * Get auth id
     *
     * @return null|integer|string
     */
    public function getId()
    {
        return $this->provider->getId();
    }

    /**
     * Return true if user is logged
     *
     * @return boolean
     */
    public function isLogged(): bool
    {
        return !empty($this->getId());
    }

    /**
     * Resolve auth type
     *
     * @param string|null|array $type
     * @return null|string
     */
    public function resolveAuthType($type): ?string
    {
        return AuthFactory::resolveAuthType($type);
    }
}   
