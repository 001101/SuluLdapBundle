<?php

namespace Sulu\Bundle\LdapBundle\Entity;

use Sulu\Bundle\SecurityBundle\Entity\UserRepository as BaseUserRepository;

/**
 * Class UserRepository
 */
class UserRepository extends BaseUserRepository
{
    /**
     * @param UserInterface $user
     */
    public function save(UserInterface $user)
    {
        $this->_em->persist($user->getContact());
        $this->_em->persist($user);
        $this->_em->flush();
    }
}
