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
     * Constructor
     * 
     * @param string            $message
     * @param int               $code
     * @param Throwable|null    $previous
     */
    public function __construct(string $message = '', int $code = 0, ?Throwable $previous = null) {
        parent::__construct($message,$code,$previous);      
    }

    /**
     * @return string
     */
    public function getTitle(): string
    {
        return $this->title;
    }

    /**
     * @return string
     */
    public function getDescription(): string
    {
        return $this->description;
    }
}
