<?php declare(strict_types = 1);

namespace SocialiteProviders\MediaWiki;

use SocialiteProviders\Manager\SocialiteWasCalled;

class MediaWikiExtendSocialite
{
    /**
     * Execute the provider.
     */
    public function handle(SocialiteWasCalled $socialiteWasCalled)
    {
        $socialiteWasCalled->extendSocialite(
            'mediawiki',
            __NAMESPACE__.'\Provider',
            __NAMESPACE__.'\Server'
        );
    }
}
