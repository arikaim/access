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

use Arikaim\Core\Access\Provider\SessionAuthProvider;
use Arikaim\Core\Collection\Arrays;
use Arikaim\Core\Access\AuthFactory;

/**
 * Manage permissions.
 */
class Access implements AccessInterface
{ 
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
     * @var AuthProviderInterface|null
     */
    private $provider;

    /**
     * Constructor
     * 
     * @param PermissionsInterface $adapter
    */
    public function __construct(
        PermissionsInterface $adapter, 
        UserProviderInterface $user, 
        ?AuthProviderInterface $provider = null
    ) 
    {
        $this->adapter = $adapter;  
        $this->user = $user;
        $this->provider = ($provider == null) ? new SessionAuthProvider($user) : $provider;   
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
    public function middleware($authName, array $options = [], ?UserProviderInterface $user = null)
    {       
        $user = $user ?? $this->user;

        return AuthFactory::createMiddleware($authName,$user,$options);       
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
        if (\is_string($provider) == true || \is_integer($provider) == true) {
            $provider = $this->createProvider($provider,$user,$params);
        }
        $this->setProvider($provider);

        return $provider;
    }

    /**
     * Create auth provider
     *
     * @param string $name
     * @param UserProviderInterface|null $user
     * @param array $params
     * @return object|null
     */
    protected function createProvider(string $name, ?UserProviderInterface $user = null, array $params = [])
    {
        $user = $user ?? $this->user;

        return AuthFactory::createProvider($name,$user,$params);       
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
     * @return AuthProviderInterface
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
        if (empty($authId) == true) {
            return false;
        }

        return $this->hasAccess(AccessInterface::CONTROL_PANEL,AccessInterface::FULL,$authId);
    }
    
    /**
     * Check access 
     *
     * @param string|int $name Permission name
     * @param string|array|null $type PermissionType (read,write,execute,delete)   
     * @param string|integer $authId 
     * @return boolean
     */
    public function hasAccess($name, $type = null, $authId = null): bool
    {       
        $authId = $authId ?? $this->getId();

        list($name,$permissionType) = $this->resolvePermissionName($name);
       
        if (\is_array($permissionType) == false) {           
            $permissionType = $this->resolvePermissionType($type);
        }
        
        if (\is_array($permissionType) == false) {
            return false;
        }

        return $this->adapter->hasPermissions($name,$authId,$permissionType);            
    }

    /**
     * Get user permissions
     *
     * @param integer|null $authId
     * @return mixed
     */
    public function getUserPermissions($authId = null)
    {
        $authId = $authId ?? $this->getId();

        return $this->adapter->getUserPermissions($authId);
    }

    /**
     * Add permission item.
     *
     * @param string $name    
     * @param string|null $title
     * @param string|null $description
     * @param string|null $extension
     * @return boolean
     */
    public function addPermission(string $name, ?string $title = null, ?string $description = null, ?string $extension = null): bool
    {
        return $this->adapter->addPermission($name,$title,$description,$extension);
    }

    /**
     * Resolve permission full name  name:type
     *
     * @param string $name
     * @return array
     */
    public function resolvePermissionName(string $name): array
    {
        $tokens = explode(':',$name);
        $name = $tokens[0];
        $type = $tokens[1] ?? AccessInterface::FULL;     

        if (\is_string($type) == true) {
            $type = (\strtolower($type) == 'full') ? AccessInterface::FULL : Arrays::toArray($type,',');
        }
        
        return [$name,$type];
    }

    /**
     * Resolve permission type
     *
     * @param string|array $type
     * @return array|null
     */
    protected function resolvePermissionType($type): ?array
    {
        if (\is_array($type) == true) {
            return $type;
        }
    
        if (\is_string($type) == true) {
            $type = Arrays::toArray($type,',');
        }

        return null;
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
    public function getUser()
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
     * @return null|integer
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
     * Return auth name
     *
     * @param int $auth
     * @return string|null
     */
    public function getAuthName($auth): ?string
    {
        return AuthFactory::getAuthName($auth);        
    }

    /**
     * Resolve auth type
     *
     * @param string|integer $type
     * @return null|integer
     */
    public function resolveAuthType($type): ?int
    {
        return AuthFactory::resolveAuthType($type);
    }
}   
