# MediaWiki Socialite Provider for Laravel

## Config
Add to `services.php`
```php
'mediawiki' => [
    'client_id' => env('WIKI_OAUTH_ID'),
    'client_secret' => env('WIKI_OAUTH_SECRET'),
    'redirect' => 'oob',
    'url' => env('WIKI_URL'),
]
```