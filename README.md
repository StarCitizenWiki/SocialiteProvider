# MediaWiki Socialite Provider for Laravel

## Config
Add to `services.php`
```php
'mediawiki' => [
    'client_id' => env('WIKI_OAUTH_ID'),
    'client_secret' => env('WIKI_OAUTH_SECRET'),
    'redirect' => 'oob',
    'url' => env('WIKI_URL'),
    'auth_type' => env('WIKI_AUTH_TYPE', 'authenticate'),
]
```

``auth_type`` accepts two values: ``authenticate`` for User Identification only or ``authorize`` for extended Access.