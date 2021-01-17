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

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;

/**
 * JSON Web Token Authentication
*/
class Jwt
{
    /**
     * JWT object
     *
     * @var object
     */
    private $token;
    
    /**
     * JWT key
     *
     * @var string
     */
    private $key;

    /**
     * Constructor
     *
     * @param int|null $expireTime Expire time stamp, default value 1 month
     */
    public function __construct($expireTime = null, string $key)
    {
        $this->key = $key;
        $this->init($expireTime);
    }

    /**
     * Init token data
     *
     * @param int|null $expireTime
     * @return void
     */
    private function init($expireTime = null): void 
    {
        $expireTime = ($expireTime == null) ? \strtotime('+1 week') : $expireTime;
        $tokenId = \base64_encode(\random_bytes(32));
       
        $this->token = new Builder();
        $this->token->setIssuer(DOMAIN);
        $this->token->setAudience(DOMAIN);
        $this->token->setId($tokenId, true);
        $this->token->setIssuedAt(time());
        $this->token->setNotBefore(time());
        $this->token->setExpiration($expireTime);
    }

    /**
     * Set token parameter
     *
     * @param string $key
     * @param mixed $value
     * @return void
     */
    public function set(string $key, $value): void 
    {        
        $this->token->set($key,$value);
    }
    
    /**
     * Create JWT token
     *
     * @return string
     */
    public function createToken(): string 
    {    
        $signer = new Sha256();
        $this->token->sign($signer,$this->key);
        
        return (string)$this->token->getToken();
    }
    
    /**
     * Decode encrypted JWT token
     *
     * @param string $token
     * @param boolean $verify
     * @return mixed
     */
    public function decodeToken(string $token, bool $verify = true)
    {
        try {
            $parser = new Parser();
            $this->token = $parser->parse($token);      
            if ($verify == true) {
                if ($this->verify($this->key) == false) {
                    // Token not valid
                    return false; 
                }
            }
            return $this->token->getClaims();
        } catch(\Exception $e) {
            return false;
        }
    }

    /**
     * Verify token data
     *
     * @return boolean
     */
    public function verify(): bool 
    {
        $signer = new Sha256();
        
        return $this->token->verify($signer,$this->key);
    }

    /**
     * Validate token data
     *
     * @param mixed $data
     * @return mixed
     */
    public function validate($data) 
    {
        return $this->token->validate($data);
    }
}
