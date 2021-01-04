<?php
/**
 * User: widdy
 * Date: 2019/10/24
 * Time: 22:03
 */

namespace ChastePhp\LaravelJwt\Auth;

class JwtTrait
{
    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJwtIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJwtCustomClaims()
    {
        return [];
    }

    /**
     * @param $payload
     * @return bool
     */
    public function customJwtCheck($payload)
    {
        return true;
    }
}
