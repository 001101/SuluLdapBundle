<?php

namespace Sulu\Bundle\LdapBundle\Entity;

use Symfony\Component\Security\Core\User\EquatableInterface;
use Sulu\Component\Security\Authentication\UserInterface as BaseUserInterface;

interface UserInterface extends BaseUserInterface, EquatableInterface, \Serializable
{
    public function getEmail();
    public function setEmail($email);

    public function getDn();
    public function setDn($dn);

    public function getCn();
    public function setCn($cn);

    public function getAttributes();
    public function setAttributes(array $attributes);
    public function getAttribute($name);

    public function __toString();
}
