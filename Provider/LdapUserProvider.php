<?php

namespace Sulu\Bundle\LdapBundle\Provider;

use Doctrine\ORM\EntityManager;
use Sulu\Bundle\ContactBundle\Entity\Contact;
use Sulu\Bundle\ContactBundle\Entity\ContactRepository;
use Sulu\Bundle\LdapBundle\Entity\UserRepository;
use Sulu\Bundle\SecurityBundle\Entity\RoleRepository;
use Sulu\Bundle\SecurityBundle\Entity\UserRole;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Sulu\Bundle\LdapBundle\Manager\LdapUserManagerInterface;
use Sulu\Bundle\LdapBundle\Entity\UserInterface as LdapUserInterface;

/**
 * Class LdapUserProvider
 */
class LdapUserProvider implements UserProviderInterface
{
    /** @var LdapUserManagerInterface */
    private $ldapManager;

    /** @var string */
    private $bindUsernameBefore;

    /** @var UserRepository */
    private $userRepository;

    /** @var ContactRepository */
    private $contactRepository;

    /** @var RoleRepository */
    private $roleRepository;

    /** @var EntityManager */
    private $entityManager;

    /** @var array */
    private $params;

    /**
     * @param UserRepository $userRepository
     * @param RoleRepository $roleRepository
     * @param ContactRepository $contactRepository
     * @param LdapUserManagerInterface $ldapManager
     * @param EntityManager $entityManager
     * @param bool|false $bindUsernameBefore
     * @param array $params
     */
    public function __construct(
        UserRepository $userRepository,
        RoleRepository $roleRepository,
        ContactRepository $contactRepository,
        LdapUserManagerInterface $ldapManager,
        EntityManager $entityManager,
        $bindUsernameBefore = false,
        array $params
    ) {
        $this->ldapManager = $ldapManager;
        $this->bindUsernameBefore = $bindUsernameBefore;
        $this->userRepository = $userRepository;
        $this->contactRepository = $contactRepository;
        $this->roleRepository = $roleRepository;
        $this->entityManager = $entityManager;
        $this->params = $params;
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByUsername($username)
    {
        // Throw the exception if the username is not provided.
        if (empty($username)) {
            throw new UsernameNotFoundException('The username is not provided.');
        }

        if ($this->bindUsernameBefore) {
            $ldapUser = $this->simpleUser($username);
        } else {
            $ldapUser = $this->anonymousSearch($username);
        }

        return $ldapUser;
    }

    /**
     * {@inheritdoc}
     */
    public function refreshUser(UserInterface $user)
    {
        $user = $this->userRepository->findUserById($user->getId());

        if (!$user instanceof LdapUserInterface) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }

        if ($this->params['client']['auth_only'] === true) {
            return $user;
        }

        if ($this->bindUsernameBefore) {
            return $this->loadUserByUsername($user->getUsername());
        } else {
            return $this->anonymousSearch($user->getUsername());
        }
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass($class)
    {
        return is_subclass_of($class, '\Sulu\Bundle\LdapBundle\Entity\UserInterface');
    }

    /**
     * @param string $username
     *
     * @return LdapUserInterface
     */
    private function simpleUser($username)
    {
        /** @var LdapUserInterface $ldapUser */
        $ldapUser = $this->userRepository->createNew();
        $ldapUser->setUsername($username);

        return $ldapUser;
    }

    private function anonymousSearch($username)
    {
        /** @var LdapUserManagerInterface $lm */
        $lm = $this->ldapManager->setUsername($username)->doPass();

        return $this->createOrUpdateDBUser($lm);
    }

    /**
     * @param LdapUserManagerInterface $ldapUser
     *
     * @return LdapUserInterface
     */
    private function createOrUpdateDBUser($ldapUser)
    {
        /** @var LdapUserInterface $dbUser */
        $dbUser = $this->userRepository->findOneBy(
            array(
                'username' => $ldapUser->getUsername(),
                'dn' => $ldapUser->getDn()
            )
        );
        if ($dbUser != null) {
            /** @var Contact $contact */
            $contact = $dbUser->getContact();
        } else {
            $dbUser = $this->userRepository->createNew();
            $contact = $this->contactRepository->createNew();
        }

        $contact->setFirstName($ldapUser->getFirstname());
        $contact->setLastName($ldapUser->getLastname());

        $dbUser
            ->setEmail($ldapUser->getEmail())
            ->setSalt('LDAP_' . rand())
            ->setPassword('LDAP' . rand())
            ->setLocale($ldapUser->getLocale())
            ->setUsername($ldapUser->getUsername())
            ->setDn($ldapUser->getDn())
            ->setCn($ldapUser->getCn())
            ->setAttributes($ldapUser->getAttributes())
            ->setEnabled($ldapUser->getEnabled())
            ->setContact($contact);

        $this->userRepository->save($dbUser);

        $this->syncRoles($ldapUser, $dbUser);

        return $dbUser;
    }

    /**
     * syncs all roles from ldap with local database
     *
     * @param LdapUserManagerInterface $ldapUser
     * @param LdapUserInterface $dbUser
     */
    private function syncRoles(LdapUserManagerInterface $ldapUser, LdapUserInterface $dbUser)
    {
        $ldapRoles = $ldapUser->getRoles();

        /** @var UserRole[] $userRoles */
        $userRoles = $dbUser->getUserRoles()->toArray();

        // get all currently assigned roles
        $dbRoles = array();
        foreach ($userRoles as $userRole) {
            $dbRoles[] = $userRole->getRole();
        }

        // ignore roles that exist on both sides (unchanged roles)
        foreach ($dbRoles as $index => $dbRole) {
            $key = array_search($dbRole, $ldapRoles);
            if ($key !== null && $key !== false) {
                unset($dbRoles[$index]);
                unset($ldapRoles[$key]);
            }
        }

        // remove all deleted roles
        foreach ($dbRoles as $dbRole) {
            foreach ($userRoles as $userRole) {
                if ($userRole->getRole() == $dbRole) {
                    $this->entityManager->remove($userRole);
                }
            }
        }
        $this->entityManager->flush();

        // add all new roles
        foreach ($ldapRoles as $ldapRole) {
            $userRole = new UserRole();
            $userRole->setUser($dbUser);
            $userRole->setRole($ldapRole);
            $userRole->setLocale('[]');

            $this->entityManager->persist($userRole);
        }
        $this->entityManager->flush();
    }
}
