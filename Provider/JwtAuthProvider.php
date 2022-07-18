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

use Psr\Http\Message\ServerRequestInterface;

use Arikaim\Core\Access\Interfaces\AuthProviderInterface;
use Arikaim\Core\Access\Provider\AuthProvider;
use Arikaim\Core\Access\Jwt;

/**
 * JWT auth provider.
 */
class JwtAuthProvider extends AuthProvider implements AuthProviderInterface
{
    /**
     * JWT token
     *
     * @var array
     */
    private $token;

    /**
     * Jwt key
     *
     * @var string
     */
    private $jwtKey;

    /**
     * Init provider
     *
     * @return void
     */
    protected function init(): void
    {
        $this->jwtKey = $this->getParam('key');
        $this->clearToken();
    }

    /**
     * Auth user
     *
     * @param array $credentials
     * @param ServerRequestInterface|null $request
     * @return bool
     */
    public function authenticate(array $credentials, ?ServerRequestInterface $request = null): bool
    {
        $token = $credentials['token'] ?? null;
        $token = (empty($token) == true) ? AuthProvider::readAuthHeader($request,true) : $token;
        if (empty($token) == true) {         
            return false;
        }

        if ($this->decodeToken($token) == false) {
            return false;
        }

        $id = $this->getTokenParam('user_id');
        if (empty($id) == true) {
            return false;
        }

        $this->user = $this->getProvider()->getUserById($id);
        
        if (\is_null($this->user) == true) {
            $this->clearToken();
            return false;
        }

        return true;
    }
  
    /**
     * Logout
     *
     * @return void
     */
    public function logout(): void
    {
        $this->user = null;
        $this->clearToken();
    }

    /**
     * Get auth id
     *
     * @return null|integer
     */
    public function getId()
    {
        return $this->getTokenParam('user_id');       
    }

    /**
     * Remove token.
     *
     * @return void
     */
    public function clearToken(): void
    {
        $this->token['decoded'] = null;
        $this->token['token'] = null;
    }

    /**
     * Return true if token is valid
     *
     * @return boolean
     */
    public function isValidToken(): bool
    {
        return !empty($this->token['decoded']);           
    }

    /**
     * Create auth token.
     *
     * @param mixed $id Auth id
     * @param integer|null $expire
     * @param string|null $key
     * @return object
     */
    public function createToken($id, ?int $expire = null, ?string $key = null) 
    {
        $key = (empty($key) == true) ? $this->jwtKey: $key;
        $jwt = new Jwt($expire,$key);
        $jwt->set('user_id',$id);   

        return $jwt->createToken();       
    }

    /**
     * Decode and save token data.
     *
     * @param string $token
     * @param int|null $expire
     * @param string|null $key
     * @return boolean
     */
    public function decodeToken(string $token, $expire = null, $key = null): bool
    {       
        $key = (empty($key) == true) ? $this->jwtKey : $key;
        $jwt = new Jwt($expire,$key);

        $decoded = $jwt->decodeToken($token);
        $decoded = ($decoded === false) ? null : $decoded;

        $this->token['token'] = $token;
        $this->token['decoded'] = $decoded;
       
        return !empty($decoded);
    }

    /**
     * Return token array data
     *
     * @return array
     */
    public function getToken(): array
    {
        return $this->token;
    }

    /**
     * Return token param from decoded token
     *
     * @param string $name
     * @return mixed|null
     */
    public function getTokenParam(string $name)
    {
        if (isset($this->token['decoded'][$name]) == false) {
            return null;
        }
        
        return (\is_object($this->token['decoded'][$name]) == true) ? $this->token['decoded'][$name]->getValue() : null;            
    }
}
