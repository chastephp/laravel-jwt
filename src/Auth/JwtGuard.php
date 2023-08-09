<?php
/**
 * User: widdy
 * Date: 2019/9/18
 * Time: 20:31
 */

namespace ChastePhp\LaravelJwt\Auth;

use Firebase\JWT\JWT;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;

class JwtGuard implements Guard
{
    use GuardHelpers;

    private $secret;
    private $ttl; // seconds
    private $algo;

    /**
     * The request instance.
     *
     * @var \Illuminate\Http\Request
     */
    protected $request;

    public function __construct(
        UserProvider $provider,
        Request $request
    ) {
        $this->request = $request;
        $this->provider = $provider;
        $this->secret = config('jwt.secret');
        if (empty($this->secret)) {
            throw new JwtException('jwt secret was invalid');
        }
        $this->algo = config('jwt.algo');
        $this->ttl = config('jwt.ttl');
    }

    public function user()
    {
        if (!is_null($this->user)) {
            return $this->user;
        }

        $user = null;

        $token = $this->getTokenForRequest();

        if (!empty($token)) {
            try {
                $payload = JWT::decode($token, $this->secret, [$this->algo]);
            } catch (\Exception $e) {
                throw new JwtException($e->getMessage());
            }

            if (!isset($payload->jti)) {
                throw new JwtException('token was invalid');
            }

            $user = $this->provider->retrieveById($payload->jti);

            if ($payload->sub !== $user::class) {
                throw new JwtException('token was invalid');
            }

            if ($user && method_exists($user, 'customJwtCheck')) {
                if (!$user->customJwtCheck($payload)) {
                    throw new JwtException('custom jwt check failed');
                };
            }
        }

        return $this->user = $user;
    }

    public function getTokenForRequest()
    {
        $token = $this->request->bearerToken();

        if (empty($token)) {
            $token = $this->request->query('token');
        }

        if (empty($token)) {
            $token = $this->request->input('token');
        }

        if (empty($token)) {
            $token = $this->request->cookie('token');
        }

        return $token;
    }

    public function validate(array $credentials = [])
    {
        if (empty($credentials)) {
            return false;
        }
        if ($user = $this->provider->retrieveByCredentials($credentials)) {
            return $this->provider->validateCredentials($user, $credentials);
        }

        return false;
    }

    public function login($user)
    {
        $this->setUser($user);

        return $this->encode();
    }

    public function refresh()
    {
        return $this->encode();
    }

    public function encode()
    {
        $time = time();
        $host = $this->request->getHost();
        $user = $this->user();
        $customClaims = method_exists($user, 'getJWTCustomClaims') ? $user->getJWTCustomClaims() : [];

        $payload = array_merge([
            'iss' => $host,
            'sub' => $user::class,
            'exp' => $time + $this->ttl
        ], $customClaims);

        // Set up id
        $payload['jti'] = $user->getJWTIdentifier();

        return JWT::encode($payload, $this->secret, $this->algo);
    }

    /**
     * Set the current request instance.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }
}
