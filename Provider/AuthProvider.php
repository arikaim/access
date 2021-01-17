<?php
/**
 * Arikaim
 *
 * @link        http://www.arikaim.com
 * @copyright   Copyright (c)  Konstantin Atanasov <info@arikaim.com>
 * @license     http://www.arikaim.com/license
 * 
 */
namespace Arikaim\Core\Access\Provider;

use Arikaim\Core\Access\Interfaces\UserProviderInterface;
use Arikaim\Core\Access\Interfaces\AuthProviderInterface;

/**
 * Auth provider base class.
 */
abstract class AuthProvider implements AuthProviderInterface
{
    /**
     * User provider
     *
     * @var UserProviderInterface
     */
    protected $userProvider;

    /**
     * Current auth user
     *
     * @var UserProviderInterface|null
    */
    protected $user;

    /**
     * Provider params
     *
     * @var array
     */
    protected $params;

    /**
     * Constructor
     *
     * @param UserProviderInterface $user
     * @param array $params
     */
    public function __construct(UserProviderInterface $userProvider, array $params = [])
    {       
        $this->userProvider = $userProvider;
        $this->user = null;
        $this->params = $params;
        $this->init();
    }

    /**
     * Init provider
     *
     * @return void
     */
    protected function init(): void
    {
    }

    /**
     * Get param
     *
     * @param string $name
     * @param mixed $default
     * @return mixed|null
     */
    public function getParam(string $name, $default = null)
    {
        return $this->parms[$name] ?? $default;
    }

    /**
     * Return user provider
     *
     * @return UserProviderInterface
     */
    public function getProvider()
    {
        return $this->userProvider;
    }

    /**
     * Get current auth user
     *
     * @return UserProviderInterface
     */
    public function getUser()
    {
        return $this->user;
    }

     /**
     * Get current auth id
     *
     * @return integer|null
     */
    public function getId()
    {
        return (empty($this->user) == false) ? $this->user->getAuthId() : null;
    }

    /**
     * Set user provider
     *
     * @return void
     */
    public function setProvider(UserProviderInterface $userProvider): void
    {
        $this->userProvider = $userProvider;
    }

    /**
     * Get login attempts 
     *
     * @return integer|null
     */
    public function getLoginAttempts(): ?int
    {
        return null;  
    }

    /**
     * Authenticate user 
     *
     * @param array $credentials
     * @return bool
     */
    abstract public function authenticate(array $credentials): bool;
    
    /**
     * Logout
     *
     * @return void
     */
    abstract public function logout(): void;
}
