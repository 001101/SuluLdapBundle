<?php

namespace Sulu\Bundle\LdapBundle\Entity;

use \Sulu\Bundle\SecurityBundle\Entity\User as BaseUser;

/**
 * Class User
 */
class User extends BaseUser implements UserInterface
{
    /** @var string */
    protected $dn;

    /** @var string */
    protected $cn;

    /** @var array */
    protected $attributes;

    /** @var string */
    protected $givenName;

    /**
     * @return string
     */
    public function getDn()
    {
        return $this->dn;
    }

    /**
     * @param string $dn
     *
     * @return User
     */
    public function setDn($dn)
    {
        $this->dn = $dn;

        return $this;
    }

    /**
     * @return string
     */
    public function getCn()
    {
        return $this->cn;
    }

    /**
     * @param string $cn
     *
     * @return User
     */
    public function setCn($cn)
    {
        $this->cn = $cn;

        return $this;
    }

    /**
     * @return array
     */
    public function getAttributes()
    {
        return $this->attributes;
    }

    /**
     * @param array $attributes
     *
     * @return User
     */
    public function setAttributes(array $attributes)
    {
        $this->attributes = $attributes;

        return $this;
    }

    /**
     * @return string
     */
    public function getGivenName()
    {
        return $this->givenName;
    }

    /**
     * @param string $givenName
     *
     * @return User
     */
    public function setGivenName($givenName)
    {
        $this->givenName = $givenName;

        return $this;
    }

    public function isEqualTo(\Symfony\Component\Security\Core\User\UserInterface $user)
    {
        if (!$user instanceof LdapUserInterface ||
            $user->getUsername() !== $this->username ||
            $user->getEmail() !== $this->getEmail() ||
            count(array_diff($user->getRoles(), $this->getRoles())) > 0 ||
            $user->getDn() !== $this->dn
        ) {
            return false;
        }

        return true;
    }

    public function getAttribute($name)
    {
        return isset($this->attributes[$name]) ? $this->attributes[$name] : null;
    }

    public function __toString()
    {
        return $this->getUserName();
    }
}
