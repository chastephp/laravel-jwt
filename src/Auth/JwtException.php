<?php
/**
 * User: widdy
 * Date: 2019/10/24
 * Time: 22:03
 */

namespace ChastePhp\LaravelJwt\Auth;

use Illuminate\Auth\AuthenticationException;

class JwtException extends AuthenticationException
{
    protected $message = 'An error occurred';
}
