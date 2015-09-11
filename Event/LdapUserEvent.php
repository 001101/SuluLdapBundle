<?php

namespace Sulu\Bundle\LdapBundle\Event;

use Symfony\Component\EventDispatcher\Event;
use Sulu\Bundle\LdapBundle\Entity\UserInterface;

/**
 * Class LdapUserEvent
 */
class LdapUserEvent extends Event
{
    private $user;

    public function __construct(UserInterface $user)
    {
        $this->user = $user;
    }

    public function getUser()
    {
        return $this->user;
    }

    public function setUser($user)
    {
        $this->user = $user;

        return $this;
    }
}
