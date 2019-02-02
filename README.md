# JWTReady
Simple Firebase\JWT wrapper


# PHP Standalone

```php
use Dusta\JWTReady\JWTReady;

require_once __DIR__ . '/../vendor/autoload.php'; 
$JWTReady = new JWTReady(['key' => 'YOUR-SECRET-KEY']);

// Return string
$jwt = $JWTReady->generate(['key' => 'value']);
// return eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJrZXkiOm51bGwsImlhdCI6bnVsbC.....

$check = $JWTReady->checkJWT($jwt);
// return ['jwt' => 'eyJ0eXAiOiJKV1QiLCJhbG....', 'payload' => [...]]

$decoded = $JWTReady->decode($jwt);
// return ['key' => 'value']
```

# Example SilmFramework

**src/routers.php**
```php
use Slim\Http\Request;
use Slim\Http\Response;

$app->get('/auth/check', function (Request $request, Response $response, array $args) {

    try {

        /** @var JWTReady $JWTReady */
        $JWTReady = $this->get('JWTReady');
        $checkJWT = $JWTReady->checkJWT();

    } catch (AuthorizationHeaderException $e) {
        return $response->withJson(['code' => 401, 'message' => 'Invalid BearerToken']);
    }

    return $response->withJson(['code' => 200])->withHeader('Bearer', $checkJWT->get('jwt'));
});

```

**src/dependencies.php**
``` php
use Dusta\JWTReady\JWTReady;

$container = $app->getContainer();

// monolog
$container['JWTReady'] = function ($c) {
    $settings = $c->get('settings')['JWTReady'];

    $JWTReady = new JWTReady($settings);
    return $JWTReady;
};
```

**src/settings.php**
```php
<?php
return [
    'settings' => [
        'displayErrorDetails' => true, // set to false in production
        'addContentLengthHeader' => false, // Allow the web server to send the content-length header

        'JWTReady' => [
            'key' => 'SecretKey',
            'iat' => null,
            'jti' => null,
            'iss' => null,
            'nbf' => null,
            'exp' => null,
            'data' => null
        ]
    ],
];

```
