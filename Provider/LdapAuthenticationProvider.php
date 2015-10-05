<?php

namespace Sulu\Bundle\LdapBundle\Provider;

use Sulu\Bundle\LdapBundle\Exception\ConnectionException;
use Sulu\Bundle\LdapBundle\Entity\UserInterface as LdapUserInterface;
use Sulu\Bundle\SecurityBundle\Entity\UserRole;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Sulu\Bundle\LdapBundle\Manager\LdapUserManagerInterface;
use Sulu\Bundle\LdapBundle\Event\LdapUserEvent;
use Sulu\Bundle\LdapBundle\Event\LdapEvents;
use Sulu\Bundle\LdapBundle\Entity\UserRepository;
use Doctrine\ORM\NoResultException;

class LdapAuthenticationProvider implements AuthenticationProviderInterface
{
    /** @var array */
    protected $params;

    /** @var UserProviderInterface */
    protected $userProvider;

    /** @var LdapUserManagerInterface */
    protected $ldapManager;

    /** @var EventDispatcherInterface */
    protected $dispatcher;

    /** @var string */
    protected $providerKey;

    /** @var bool */
    protected $hideUserNotFoundExceptions;

    /** @var array */
    protected $config;

    /** @var UserRepository */
    private $userRepository;

    /**
     * Constructor
     *
     * Please note that $hideUserNotFoundExceptions is true by default in order
     * to prevent a possible brute-force attack.
     *
     * @param UserProviderInterface $userProvider
     * @param AuthenticationProviderInterface $daoAuthenticationProvider
     * @param LdapUserManagerInterface $ldapManager
     * @param EventDispatcherInterface $dispatcher
     * @param string $providerKey
     * @param bool $hideUserNotFoundExceptions
     * @param array $config
     * @param array $params
     * @param UserRepository $userRepository
     */
    public function __construct(
        UserProviderInterface $userProvider,
        AuthenticationProviderInterface $daoAuthenticationProvider,
        LdapUserManagerInterface $ldapManager,
        EventDispatcherInterface $dispatcher = null,
        $providerKey,
        $hideUserNotFoundExceptions = true,
        $config,
        array $params,
        UserRepository $userRepository
    ) {
        $this->userProvider = $userProvider;
        $this->daoAuthenticationProvider = $daoAuthenticationProvider;
        $this->ldapManager = $ldapManager;
        $this->dispatcher = $dispatcher;
        $this->providerKey = $providerKey;
        $this->hideUserNotFoundExceptions = $hideUserNotFoundExceptions;
        $this->config = $config;
        $this->params = $params;
        $this->userRepository = $userRepository;
    }

    /**
     * @param TokenInterface $token
     *
     * @return null|TokenInterface|UsernamePasswordToken
     *
     * @throws \Exception
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            throw new AuthenticationException('Unsupported token');
        }

        try {
            if ($this->params['client']['auth_only']) {
                $this->handleAuthOnly($token);
            }

            /** @var LdapUserInterface $user */
            $user = $this->userProvider->loadUserByUsername($token->getUsername());

            /** @var UserRole[] $userRoles */
            $userRoles = $user->getUserRoles()->toArray();

            $hasAllowedRole = false;
            foreach ($userRoles as $userRole) {
                if (in_array($userRole->getRole()->getName(), $this->config['allowed_roles']) ) {
                    $hasAllowedRole = true;
                    break;
                }
            }

            if (!$hasAllowedRole) {
                throw new BadCredentialsException('Insufficent privileges');
            }

            if ($user instanceof LdapUserInterface) {
                $token = $this->ldapAuthenticate($user, $token);

                return $token;
            }

        } catch (\Exception $e) {
            if ($e instanceof ConnectionException ||
                $e instanceof UsernameNotFoundException ||
                $e instanceof NoResultException
            ) {
                if ($this->hideUserNotFoundExceptions) {
                    throw new BadCredentialsException('Bad credentials', 0, $e);
                }
            }

            throw $e;
        }

        if ($user instanceof LdapUserInterface) {
            return $this->daoAuthenticationProvider->authenticate($token);
        }
    }

    /**
     * Only auth user via ldap.
     *
     * @param TokenInterface $token
     */
    private function handleAuthOnly(TokenInterface $token)
    {
        $status = 0;
        $userName = $token->getUser();
        if (isset($this->params['client']['login_domain'])) {
            $domain = $this->params['client']['login_domain'];
            $loginName = $userName . '@' . $domain;
        }
        $status = $this->bind($loginName, $token);

        $user = null;
        if ($status) {
            $user = $this->userRepository->findUserByUsername($token->getUser());
        }
        if ($user) {
            $token = new UsernamePasswordToken(
                $user,
                null,
                $this->providerKey,
                $user->getRoles()
            );
        } else {
            throw new BadCredentialsException('Bad credentials', 0, $e);
        }

        return $token;
    }

    /**
     * Authentication logic to allow Ldap user
     *
     * @param LdapUserInterface $user
     * @param TokenInterface $token
     *
     * @return TokenInterface|UsernamePasswordToken
     */
    private function ldapAuthenticate(LdapUserInterface $user, TokenInterface $token)
    {
        $userEvent = new LdapUserEvent($user);
        if ($this->dispatcher != null) {
            try {
                $this->dispatcher->dispatch(LdapEvents::PRE_BIND, $userEvent);
            } catch (AuthenticationException $expt) {
                if ($this->hideUserNotFoundExceptions) {
                    throw new BadCredentialsException('Bad credentials', 0, $expt);
                }

                throw $expt;
            }
        }

        $this->bind($user->getUsername(), $token);

        if ($user->getDn() === null) {
            $user = $this->reloadUser($user);
        }

        if ($this->dispatcher !== null) {
            $userEvent = new LdapUserEvent($user);
            try {
                $this->dispatcher->dispatch(LdapEvents::POST_BIND, $userEvent);
            } catch (AuthenticationException $authenticationException) {
                if ($this->hideUserNotFoundExceptions) {
                    throw new BadCredentialsException('Bad credentials', 0, $authenticationException);
                }
                throw $authenticationException;
            }
        }

        $token = new UsernamePasswordToken(
            $userEvent->getUser(),
            null,
            $this->providerKey,
            $userEvent->getUser()->getRoles()
        );

        return $token;
    }

    /**
     * Authenticate the user with LDAP bind.
     *
     * @param string $username
     * @param TokenInterface $token
     *
     * @return true
     */
    private function bind($username, TokenInterface $token)
    {
        if ($token->getCredentials() != null) {
            $this->ldapManager
                ->setUsername($username)
                ->setPassword($token->getCredentials());
            if (isset($this->params['client']['auth_only']) &&
                $this->params['client']['auth_only'] === true) {
                $this->ldapManager->bindByUsername();
            } else {
                $this->ldapManager->auth();
            }
        }

        return true;
    }

    /**
     * Reload user with the username
     *
     * @param LdapUserInterface $user
     *
     * @return LdapUserInterface $user
     */
    private function reloadUser(LdapUserInterface $user)
    {
        try {
            $user = $this->userProvider->refreshUser($user);
        } catch (UsernameNotFoundException $userNotFoundException) {
            if ($this->hideUserNotFoundExceptions) {
                throw new BadCredentialsException('Bad credentials', 0, $userNotFoundException);
            }

            throw $userNotFoundException;
        }

        return $user;
    }

    /**
     * Check whether this provider supports the given token.
     *
     * @param TokenInterface $token
     *
     * @return boolean
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof UsernamePasswordToken && $token->getProviderKey() === $this->providerKey;
    }
}
