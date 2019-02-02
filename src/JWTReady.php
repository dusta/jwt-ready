<?php

namespace Dusta\JWTReady;

use Dusta\JWTReady\Data\Collection;
use Dusta\JWTReady\Exception\AuthorizationHeaderException;

/**
 * Class JWTReady
 *
 * @author Sławomir Kaleta <slaszka@gmail.com>
 */
class JWTReady
{

    /**
     * @var int
     */
    private $iat;

    /**
     * @var string
     */
    private $jti;

    /**
     * @var string
     */
    private $iss;

    /**
     * @var int
     */
    private $nbf;

    /**
     * @var int
     */
    private $exp;

    /**
     * @var array
     */
    private $data;

    /**
     * @var Collection
     */
    private $Collection;

    /**
     * @var array
     */
    private $payload;

    /**
     * @var array
     */
    private $allowedAlgorithms;

    /**
     * @var string
     */
    private $key;

    /**
     * JWT constructor.
     *
     * @param array $data
     */
    public function __construct(array $data = [])
    {

        $this->Collection = new Collection($data);

        $this->key = $this->Collection->get('key');
        $this->iat = $this->Collection->get('iat', \time());
        $this->jti = $this->Collection->get('jti', base64_encode(openssl_random_pseudo_bytes(32)));
        $this->iss = $this->Collection->get('iss', $_SERVER['SERVER_NAME']);
        $this->nbf = $this->Collection->get('nbf', $this->iat - 1);
        $this->exp = $this->Collection->get('exp', $this->nbf + 1500);
        $this->data = $this->Collection->get('data', []);

        $this->payload = [
            'key' => $this->key,
            'iat' => $this->iat,
            'jti' => $this->jti,
            'iss' => $this->iss,
            'nbf' => $this->nbf,
            'exp' => $this->exp,
            'data' => $this->data,
        ];

        $this->allowedAlgorithms = $this->Collection->get('allowedAlgorithms', ['HS512']);

    }

    /**
     * @param $data
     *
     * @return string
     */
    public function generate(array $data)
    {
        $this->payload['data'] = $data;

        $jwt = \Firebase\JWT\JWT::encode(
            $this->payload,             //Data to be encoded in the JWT
            $this->key,           // The signing key
            'HS512'                     // Algorithm used to sign the token
        );

        return $jwt;
    }

    /**
     * @return bool
     */
    private function isExpired()
    {
        return $this->iat + $this->Collection->get('extendAfter', 60 * 60) < \time();
    }

    /**
     * @param null $token
     *
     * @return Collection
     */
    public function checkJWT($bearerToken = null)
    {
        $return = [];

        if ($bearerToken === null) {
            $bearerToken = $this->getBearerToken();
            if ($bearerToken === null) {
                throw new AuthorizationHeaderException;
            }
        }

        $decodedJWT = $this->decode($bearerToken);
        if ($decodedJWT === null) {
            $return['error'] = 401;

        } elseif ($this->isExpired()) {
            $this->data = $decodedJWT->data;

            $jwt = \Firebase\JWT\JWT::encode(
                $this->payload,
                $this->key,
                'HS512'
            );

            $return['jwt'] = $jwt;
        }

        if (!empty($decodedJWT->data)) {
            $return['payload'] = $decodedJWT->data;
        }

        return new Collection($return);
    }

    /**
     * @param $token
     *
     * @return object|null
     */
    private function decode($token)
    {
        try {
            $decoded = \Firebase\JWT\JWT::decode($token, $this->key, $this->allowedAlgorithms);
        } catch (\Exception $e) {
            return null;
        }

        return $decoded;
    }


    /**
     * Get header Authorization
     **/
    public function getAuthorizationHeader()
    {
        $headers = null;
        if (isset($_SERVER['Authorization'])) {
            $headers = trim($_SERVER["Authorization"]);
        } else {
            if (isset($_SERVER['HTTP_AUTHORIZATION'])) { //Nginx or fast CGI
                $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
            } elseif (function_exists('apache_request_headers')) {
                $requestHeaders = apache_request_headers();
                // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
                $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)),
                    array_values($requestHeaders));
                //print_r($requestHeaders);
                if (isset($requestHeaders['Authorization'])) {
                    $headers = trim($requestHeaders['Authorization']);
                }
            }
        }
        return $headers;
    }

    /**
     * Get access token from header
     */
    public function getBearerToken()
    {
        $headers = $this->getAuthorizationHeader();
        // HEADER: Get the access token from the header
        if (!empty($headers)) {
            if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
                return $matches[1];
            }
        }
        return null;
    }

}