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

class AccessDeniedException extends Exception
{
    /**
     * @var object
     */
    protected $request;

    /**
     * @var string
     */
    protected $title = '';

    /**
     * @var string
     */
    protected $description = '';

    /**
     * @param object            $request
     * @param string            $message
     * @param int               $code
     * @param Throwable|null    $previous
     */
    public function __construct($request, string $message = '', int $code = 0, ?Throwable $previous = null) {
        parent::__construct($message,$code,$previous);
        $this->request = $request;
    }

    /**
     * @return object
    */
    public function getRequest()
    {
        return $this->request;
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
