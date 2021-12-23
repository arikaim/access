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

use Psr\Http\Message\ResponseInterface;

use Exception;
use Throwable;

/**
 * Access denied exception class
 */
class AccessDeniedException extends Exception
{
    /**
     * @var string
     */
    protected $title = '';

    /**
     * @var string
     */
    protected $description = '';

    /**
     * Response
     *
     * @var ResponseInterface|null
     */
    protected $response = null;

    /**
     * Constructor
     * 
     * @param string            $message
     * @param ResponseInterface|null $response
     * @param int               $code
     * @param Throwable|null    $previous
     */
    public function __construct(
        string $message = '', 
        ?ResponseInterface $response = null,
        int $code = 0, 
        ?Throwable $previous = null
    ) 
    {
        parent::__construct($message,$code,$previous);  
        $this->response = $response;   
    }

    /**
     * Get response
     *
     * @return ResponseInterface|null
     */
    public function getResponse(): ?ResponseInterface
    {
        return $this->response;
    }

    /**
     * Get title
     * @return string
     */
    public function getTitle(): string
    {
        return $this->title;
    }

    /**
     * Get description
     * @return string
     */
    public function getDescription(): string
    {
        return $this->description;
    }
}
