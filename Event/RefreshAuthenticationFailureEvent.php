<?php

/*
 * This file is part of the GesdinetJWTRefreshTokenBundle package.
 *
 * (c) Gesdinet <http://www.gesdinet.com/>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Gesdinet\JWTRefreshTokenBundle\Event;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class RefreshAuthenticationFailureEvent extends Event
{
    private AuthenticationException $exception;

    private Response $response;

    public function __construct(AuthenticationException $exception, Response $response)
    {
        $this->exception = $exception;
        $this->response = $response;
    }

    public function getException(): AuthenticationException
    {
        return $this->exception;
    }

    public function getResponse(): Response
    {
        return $this->response;
    }

    public function setResponse(Response $response): void
    {
        $this->response = $response;
    }
}
