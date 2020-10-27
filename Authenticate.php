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

use Arikaim\Core\Access\Provider\SessionAuthProvider;

use Arikaim\Core\Access\Interfaces\UserProviderInterface;
use Arikaim\Core\Access\Interfaces\AuthProviderInterface;
use Arikaim\Core\Interfaces\Access\AuthInterface;
use Arikaim\Core\Interfaces\Access\AccessInterface;

use Arikaim\Core\Access\AuthFactory;

/**
 * Manage auth.
 */
class Authenticate implements AuthInterface
{
    /**
     * Auth provider variable
     *
     * @var AuthProviderInterface
     */
    private $provider;

    /**
     * Auth user
     *
     * @var UserProviderInterface
     */
    private $user;

    /**
     * Permissins manager
     *
     * @var AccessInterface
     */
    private $access;

    /**
     * Constructor
     *
     * @param UserProviderInterface $user
     * @param AccessInterface $access
     * @param AuthProviderInterface $provider
     */
    public function __construct(
        UserProviderInterface $user, 
        AccessInterface $access, 
        AuthProviderInterface $provider = null)
    {       
        $this->user = $user;
        $this->provider = ($provider == null) ? new SessionAuthProvider($user) : $provider;   
        $this->access = $access;
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
    public function addPermission($name, $title = null, $description = null, $extension = null)
    {
        return $this->access->addPermission($name,$title,$description,$extension);
    }

    /**
     * Full Permissions 
     *
     * @return array
     */
    public function getFullPermissions()
    {
        return $this->access->getFullPermissions();
    }

    /**
     * Control panel permission name
     *
     * @return string
     */
    public function getControlPanelPermission()
    {
        return $this->access->getControlPanelPermission();
    }

    /**
     * Check if current loged user have control panel access
     *
     * @return boolean
     */
    public function hasControlPanelAccess($authId = null)
    {
        $authId = (empty($authId) == true) ? $this->getId() : $authId;

        return (empty($authId) == true) ? false : $this->access->hasControlPanelAccess($authId);
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

        return $this->access->getUserPermissions($authId);     
    }

    /**
     * Check access 
     *
     * @param string $name Permission name
     * @param string|array $type PermissionType (read,write,execute,delete)    
     * @return boolean
    */
    public function hasAccess($name, $type = null, $authId = null)
    {
        $authId = $authId ?? $this->getId();
      
        return (empty($authId) == true) ? false : $this->access->hasAccess($name,$type,$authId);
    }
    
    /**
     * Resolve permission full name  name:type
     *
     * @param string $name
     * @return array
     */
    public function resolvePermissionName($name)
    {
        return $this->access->resolvePermissionName($name);
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
     * Change auth provider
     *
     * @param AuthProviderInterface|string $provider
     * @param UserProviderInterface|null $user
     * @param array $params
     * @return AuthProviderInterface
     */
    public function withProvider($provider, $user = null, $params = [])
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
    protected function createProvider($name, UserProviderInterface $user = null, $params = [])
    {
        $user = $user ?? $this->user;
        return AuthFactory::createProvider($name,$user,$params);       
    }

    /**
     * Create auth middleware
     *
     * @param string $authName
     * @param array $options
     * @param UserProviderInterface|null $user
     * @return object|null
     */
    public function middleware($authName, $options = [], UserProviderInterface $user = null)
    {       
        $user = $user ?? $this->user;

        return AuthFactory::createMiddleware($authName,$user,$options);       
    }

    /**
     * Auth user 
     *
     * @param array $credentials
     * @return bool
     */
    public function authenticate(array $credentials)
    {
        return $this->provider->authenticate($credentials);
    }
    
    /**
     * Logout
     *
     * @return void
     */
    public function logout()
    {
        $this->provider->logout();
    }

    /**
     * Get logged user
     *
     * @return mixed|null
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
    public function getLoginAttempts()
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
    public function isLogged()
    {
        return !empty($this->getId());
    }

    /**
     * Return auth name
     *
     * @param int $auth
     * @return string
     */
    public function getAuthName($auth)
    {
        return AuthFactory::getAuthName($auth);        
    }

    /**
     * Resolve auth type
     *
     * @param string|integer $type
     * @return null|integer
     */
    public function resolveAuthType($type)
    {
        return AuthFactory::resolveAuthType($type);
    }
}
