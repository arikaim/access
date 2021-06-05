<?php
/**
 * Arikaim
 *
 * @link        http://www.arikaim.com
 * @copyright   Copyright (c)  Konstantin Atanasov <info@arikaim.com>
 * @license     http://www.arikaim.com/license
 * 
*/
namespace Arikaim\Core\Access\Interfaces;

/**
 * Auth tokens interface
 */
interface AutoTokensInterface
{    
    /**
     * Token access type
     */
    const PAGE_ACCESS_TOKEN  = 0;
    const LOGIN_ACCESS_TOKEN = 1;
    const API_ACCESS_TOKEN   = 2;
    const OAUTH_ACCESS_TOKEN = 3;
}
