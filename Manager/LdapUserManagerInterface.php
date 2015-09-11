<?php

namespace Sulu\Bundle\LdapBundle\Manager;

use Sulu\Bundle\LdapBundle\Entity\User;
use Sulu\Bundle\LdapBundle\Exception\ConnectionException;
use Sulu\Component\Security\Authentication\RoleRepositoryInterface;

interface LdapUserManagerInterface
{
    /**
     * @param LdapConnectionInterface $conn
     * @param RoleRepositoryInterface $roleRepository
     */
    function __construct(LdapConnectionInterface $conn, RoleRepositoryInterface $roleRepository);

    /**
     * @param string $username
     */
    function exists($username);

    /**
     * @throws ConnectionException
     */
    function auth();

    /**
     * @return LdapUserManagerInterface
     */
    function doPass();

    /**
     * @return string
     */
    function getDn();

    /**
     * @return string
     */
    function getCn();

    /**
     * @return string
     */
    function getEmail();

    /**
     * @return array
     */
    function getAttributes();

    /**
     * @return User
     */
    function getLdapUser();

    /**
     * @return string
     */
    function getDisplayName();

    /**
     * @return string
     */
    function getUsername();

    /**
     * @return array
     */
    function getRoles();

    /**
     * @return string
     */
    function getFirstname();

    /**
     * @return string
     */
    function getLastname();

    /**
     * @return string
     */
    function getLocale();

    /**
     * @return bool
     */
    function getEnabled();

    /**
     * @param string $username
     *
     * @return LdapUserManagerInterface
     */
    function setUsername($username);

    /**
     * @param string $password
     *
     * @return LdapUserManagerInterface
     */
    function setPassword($password);
}
