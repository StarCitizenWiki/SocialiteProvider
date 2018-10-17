<?php declare(strict_types = 1);

namespace SocialiteProviders\MediaWiki;

use GuzzleHttp\Exception\BadResponseException;
use League\OAuth1\Client\Credentials\TokenCredentials;
use SocialiteProviders\Manager\OAuth1\Server as BaseServer;
use SocialiteProviders\Manager\OAuth1\User;

/**
 * Class Server
 */
class Server extends BaseServer
{
    private const SERVICES_MEDIAWIKI_URL = 'services.mediawiki.url';
    private const SERVICES_MEDIAWIKI_AUTH_TYPE = 'service.mediawiki.auth_type';

    const AUTH_TYPE_AUTHORIZE = 'authorize';
    const AUTH_TYPE_AUTHENTICATE = 'authenticate';

    /**
     * @var string Needed Title Param for MediaWiki
     */
    protected $title;

    /**
     * {@inheritDoc}
     */
    public function urlTemporaryCredentials()
    {
        $this->title = 'Special:OAuth/initiate';

        return sprintf('%s/%s', config(self::SERVICES_MEDIAWIKI_URL), $this->title);
    }

    /**
     * {@inheritDoc}
     */
    public function urlAuthorization()
    {
        if (config(self::SERVICES_MEDIAWIKI_AUTH_TYPE, self::AUTH_TYPE_AUTHENTICATE) === self::AUTH_TYPE_AUTHENTICATE) {
            $authType = self::AUTH_TYPE_AUTHENTICATE;
        } else {
            $authType = self::AUTH_TYPE_AUTHORIZE;
        }

        $this->title = "Special:OAuth/{$authType}";

        return sprintf('%s/%s', config(self::SERVICES_MEDIAWIKI_URL), $this->title);
    }

    /**
     * {@inheritDoc}
     */
    public function urlTokenCredentials()
    {
        $this->title = 'Special:OAuth/token';

        return sprintf('%s/%s', config(self::SERVICES_MEDIAWIKI_URL), $this->title);
    }

    /**
     * {@inheritDoc}
     */
    public function urlUserDetails()
    {
        $this->title = 'Special:OAuth/identify';

        return sprintf('%s/%s', config(self::SERVICES_MEDIAWIKI_URL), $this->title);
    }

    /**
     * {@inheritDoc}
     */
    public function userDetails($data, TokenCredentials $tokenCredentials)
    {
        $user = new User();
        $user->id = $data->sub;
        $user->email = optional($data)->email;
        $user->username = $data->username;
        $user->blocked = $data->blocked;

        $user->extra = [
            'groups' => $data->groups,
            'rights' => $data->rights,
            'grants' => optional($data)->grants,
            'editcount' => $data->editcount,
        ];

        return $user;
    }

    /**
     * {@inheritDoc}
     */
    public function userUid($data, TokenCredentials $tokenCredentials)
    {
        return $data['id'];
    }

    /**
     * {@inheritDoc}
     */
    public function userEmail($data, TokenCredentials $tokenCredentials)
    {
        return $data['email'] ?? null;
    }

    /**
     * {@inheritDoc}
     */
    public function userScreenName($data, TokenCredentials $tokenCredentials)
    {
        return $data['username'];
    }

    /**
     * Fetch user details from the remote service.
     *
     * @param TokenCredentials $tokenCredentials
     * @param bool             $force
     *
     * @return array HTTP client response
     *
     * @throws \Exception
     * @throws \InvalidArgumentException
     */
    protected function fetchUserDetails(TokenCredentials $tokenCredentials, $force = true)
    {
        if (!$this->cachedUserDetailsResponse || $force) {
            $url = $this->urlUserDetails();

            $client = $this->createHttpClient();

            $headers = $this->getHeaders($tokenCredentials, 'GET', $url);

            try {
                $response = $client->get(
                    $url,
                    [
                        'headers' => $headers,
                    ]
                );
            } catch (BadResponseException $e) {
                $response = $e->getResponse();
                $body = $response->getBody();
                $statusCode = $response->getStatusCode();

                throw new \Exception(
                    "Received error [$body] with status code [$statusCode] when retrieving token credentials."
                );
            }

            // There are three fields in the response
            $fields = explode('.', (string) $response->getBody());
            if (count($fields) !== 3) {
                throw new \InvalidArgumentException("Invalid Data");
            }

            $this->validateHeader($fields[0]);

            $this->verifySignature($fields[2], $fields[0].'.'.$fields[1]);

            $this->cachedUserDetailsResponse = $this->decodePayload($fields[1]);
        }

        return $this->cachedUserDetailsResponse;
    }

    /**
     * Overwritten to include call to additionalProtocolParameters
     *
     * Generate the OAuth protocol header for a temporary credentials
     * request, based on the URI.
     *
     * @param string $uri
     *
     * @return string
     */
    protected function temporaryCredentialsProtocolHeader($uri)
    {
        $parameters = array_merge(
            $this->baseProtocolParameters(),
            [
                'oauth_callback' => $this->clientCredentials->getCallbackUri(),
            ],
            $this->additionalProtocolParameters()
        );

        $parameters['oauth_signature'] = $this->signature->sign($uri, $parameters, 'POST');

        return $this->normalizeProtocolParameters($parameters);
    }

    /**
     * The additional Params
     *
     * @return array
     */
    protected function additionalProtocolParameters()
    {
        return [
            'title' => $this->title,
        ];
    }

    /**
     * Validate the header. MWOAuth always returns alg "HS256".
     *
     * @param string $header
     */
    private function validateHeader($header)
    {
        $header = base64_decode(strtr($header, '-_', '+/'), true);

        if (false !== $header) {
            $header = json_decode($header);
        }

        if (!is_object($header) || $header->typ !== 'JWT' || $header->alg !== 'HS256') {
            throw new \InvalidArgumentException("Invalid Header");
        }
    }

    /**
     * Verify the Signature
     *
     * @param string $signature
     * @param string $data
     */
    private function verifySignature($signature, $data)
    {
        $sig = base64_decode(strtr($signature, '-_', '+/'), true);
        $check = hash_hmac('sha256', $data, $this->clientCredentials->getSecret(), true);

        if ($sig !== $check) {
            throw new \InvalidArgumentException("Invalid Signature");
        }
    }

    /**
     * Decode the payload
     *
     * @param string $payload
     *
     * @return array
     */
    private function decodePayload($payload)
    {
        $payload = base64_decode(strtr($payload, '-_', '+/'), true);

        if (false !== $payload) {
            $payload = json_decode($payload);
        }

        if (!is_object($payload)) {
            throw new \InvalidArgumentException("Invalid Payload");
        }

        if ($payload->iss !== config(self::SERVICES_MEDIAWIKI_URL)) {
            throw new \InvalidArgumentException(
                "Got Issuer {$payload->iss} expected ".config(self::SERVICES_MEDIAWIKI_URL)
            );
        }

        return $payload;
    }
}
