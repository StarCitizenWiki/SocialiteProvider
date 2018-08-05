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
    private const TITLE_PARAM = 'title';
    private const SERVICES_MEDIAWIKI_URL = 'services.mediawiki.url';

    /**
     * {@inheritDoc}
     */
    public function urlTemporaryCredentials()
    {
        $this->parameters = [
            self::TITLE_PARAM => 'Special:OAuth/initiate',
        ];

        return config(self::SERVICES_MEDIAWIKI_URL).'/Special:OAuth/initiate';
    }

    /**
     * {@inheritDoc}
     */
    public function urlAuthorization()
    {
        $this->parameters = [
            self::TITLE_PARAM => 'Special:OAuth/authenticate',
        ];

        return config(self::SERVICES_MEDIAWIKI_URL).'/Special:OAuth/authenticate';
    }

    /**
     * {@inheritDoc}
     */
    public function urlTokenCredentials()
    {
        $this->parameters = [
            self::TITLE_PARAM => 'Special:OAuth/token',
        ];

        return config(self::SERVICES_MEDIAWIKI_URL).'/Special:OAuth/token';
    }

    /**
     * {@inheritDoc}
     */
    public function urlUserDetails()
    {
        $this->parameters = [
            self::TITLE_PARAM => 'Special:OAuth/identify',
        ];

        return config(self::SERVICES_MEDIAWIKI_URL).'/Special:OAuth/identify';
    }

    /**
     * {@inheritDoc}
     */
    public function userDetails($data, TokenCredentials $tokenCredentials)
    {
        $user = new User();
        $user->id = $data->sub;
        $user->username = $data->username;
        $user->blocked = $data->blocked;

        $user->extra = [
            'groups' => $data->groups,
            'rights' => $data->rights,
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
        return null;
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

        return $payload;
    }
}
