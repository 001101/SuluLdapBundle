<?php

namespace Sulu\Bundle\LdapBundle\EventListener;

use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Form\Extension\Csrf\CsrfProvider\CsrfProviderInterface;
use Symfony\Component\HttpFoundation\Request;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;

/**
 * Class LdapListener
 */
class LdapListener extends AbstractAuthenticationListener
{
    public function __construct(SecurityContextInterface $securityContext,
                                AuthenticationManagerInterface $authenticationManager,
                                SessionAuthenticationStrategyInterface $sessionStrategy,
                                HttpUtils $httpUtils,
                                $providerKey,
                                AuthenticationSuccessHandlerInterface $successHandler = null,
                                AuthenticationFailureHandlerInterface $failureHandler = null,
                                array $options = array(),
                                LoggerInterface $logger = null,
                                EventDispatcherInterface $dispatcher = null,
                                CsrfProviderInterface $csrfProvider = null)
    {
        parent::__construct(
            $securityContext,
            $authenticationManager,
            $sessionStrategy,
            $httpUtils,
            $providerKey,
            $successHandler,
            $failureHandler,
            array_merge(array(
                'username_parameter' => '_username',
                'password_parameter' => '_password',
                'csrf_parameter'     => '_csrf_token',
                'intention'          => 'ldap_authenticate',
                'post_only'          => true,
            ), $options),
            $logger,
            $dispatcher
        );
        
        $this->csrfProvider = $csrfProvider;
    }

    /**
     * {@inheritdoc}
     */
    protected function requiresAuthentication(Request $request)
    {
        if ($this->options['post_only'] && !$request->isMethod('post')) {
            return false;
        }

        return parent::requiresAuthentication($request);
    }

    /**
     * @param Request $request
     *
     * @return null|\Symfony\Component\Security\Core\Authentication\Token\TokenInterface
     */
    public function attemptAuthentication(Request $request)
    {
        if ($this->options['post_only'] && 'post' !== strtolower($request->getMethod())) {
            if ($this->logger !== null) {
                $this->logger->debug(sprintf('Authentication method not supported: %s.', $request->getMethod()));
            }

            return null;
        }

        if ($this->csrfProvider !== null) {
            $csrfToken = $request->get($this->options['csrf_parameter'], null, true);

            if ($this->csrfProvider->isCsrfTokenValid($this->options['intention'], $csrfToken) === false) {
                throw new InvalidCsrfTokenException('Invalid CSRF token.');
            }
        }

        $username = trim($request->get($this->options['username_parameter'], null, true));
        $password = $request->get($this->options['password_parameter'], null, true);

        $request->getSession()->set(SecurityContextInterface::LAST_USERNAME, $username);

        return $this->authenticationManager->authenticate(
            new UsernamePasswordToken($username, $password, $this->providerKey)
        );
    }
}
