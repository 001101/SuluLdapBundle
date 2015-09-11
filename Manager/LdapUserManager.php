<?php

namespace Sulu\Bundle\LdapBundle\Manager;

use Sulu\Bundle\LdapBundle\Entity\User;
use Sulu\Component\Security\Authentication\RoleRepositoryInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Sulu\Bundle\LdapBundle\Exception\ConnectionException;

class LdapUserManager implements LdapUserManagerInterface
{
    /** @var LdapConnectionInterface */
    private $ldapConnection;

    /** @var string */
    private $username;

    /** @var string */
    private $password;

    /** @var array */
    private $params;

    /** @var User */
    private $ldapUser;

    /** @var RoleRepositoryInterface */
    private $roleRepository;

    /**
     * @param LdapConnectionInterface $conn
     */
    public function __construct(LdapConnectionInterface $conn, RoleRepositoryInterface $roleRepository)
    {
        $this->ldapConnection = $conn;
        $this->params = $this->ldapConnection->getParameters();
        $this->roleRepository = $roleRepository;
    }

    /**
     * @param $username
     */
    public function exists($username)
    {
        $this->setUsername($username);
        $this->addLdapUser();
    }

    /**
     * @throws ConnectionException
     */
    public function auth()
    {
        if (strlen($this->password) === 0) {
            throw new ConnectionException('Password can\'t be empty');
        }
        
        if ($this->ldapUser === null) {
            $this->bindByUsername();
            $this->doPass();
        } else {
            $this->doPass();
            $this->bindByDn();
        }        
    }

    /**
     * @return LdapUserManagerInterface
     */
    public function doPass()
    {
        $this->addLdapUser();
        $this->addLdapRoles();

        return $this;
    }

    /**
     * @return string
     */
    public function getDn()
    {
        return $this->ldapUser['dn'];
    }

    /**
     * @return string
     */
    public function getCn()
    {
        return $this->ldapUser['cn'][0];
    }

    /**
     * @return string
     */
    public function getEmail()
    {
        return isset($this->ldapUser['mail'][0]) ? $this->ldapUser['mail'][0] : '';
    }

    /**
     * @return array
     */
    public function getAttributes()
    {
        $attributes = array();
        foreach ($this->params['user']['attributes'] as $attrName) {
            if (isset($this->ldapUser[$attrName][0])) {
                $attributes[$attrName] = $this->ldapUser[$attrName][0];
            }
        }

        return $attributes;
    }

    /**
     * @return User
     */
    public function getLdapUser()
    {
        return $this->ldapUser;
    }

    /**
     * @return string
     */
    public function getDisplayName()
    {
        if (isset($this->ldapUser['displayname'][0])) {
            return $this->ldapUser['displayname'][0];
        } else {
            return false;
        }
    }

    /**
     * @return string
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * @return array
     */
    public function getRoles()
    {
        return $this->ldapUser['roles'];
    }

    /**
     * @return string
     */
    public function getFirstname()
    {
        $firstname = null;
        $attribute = $this->params['user']['mapping']['firstname'];
        if (isset($this->ldapUser[$attribute][0])) {
            $firstname = $this->ldapUser[$attribute][0];
        }
        return $firstname;
    }

    /**
     * @return string
     */
    public function getLastname()
    {
        $lastname = null;
        $attribute = $this->params['user']['mapping']['lastname'];
        if (isset($this->ldapUser[$attribute][0])) {
            $lastname = $this->ldapUser[$attribute][0];
        }
        return $lastname;
    }

    /**
     * @return string
     */
    public function getLocale()
    {
        $locale = 'en';
        $attribute = $this->params['user']['mapping']['locale'];
        if (isset($this->ldapUser[$attribute][0])) {
            $locale = $this->ldapUser[$attribute][0];
        }
        return $locale;
    }

    /**
     * @return bool
     */
    public function getEnabled()
    {
        $enabled = false;
        $attribute = $this->params['user']['mapping']['enabled'];
        if (isset($this->ldapUser[$attribute][0])) {
            $status = intval($this->ldapUser[$attribute][0]);

            // TODO add support for OpenLDAP
            // Microsoft Active Directory specifies the flag 0x00000002 as "disabled"
            $enabled = ($status & 0x00000002) == 0;
        }

        return $enabled;
    }

    /**
     * @param string $username
     *
     * @return LdapUserManagerInterface
     */
    public function setUsername($username)
    {
        // * is wildcard - we dont allow this for authentication
        if ($username === "*") {
            throw new \InvalidArgumentException("Invalid username given.");
        }

        $this->username = $username;

        return $this;
    }

    /**
     * @param string $password
     *
     * @return LdapUserManagerInterface
     */
    public function setPassword($password)
    {
        $this->password = $password;

        return $this;
    }

    /**
     * @return mixed LdapUserManager
     *
     * @throws \Symfony\Component\Security\Core\Exception\UsernameNotFoundException
     * @throws \RuntimeException
     * @throws \Sulu\Bundle\LdapBundle\Exception\ConnectionException
     */
    private function addLdapUser()
    {
        if (!$this->username) {
            throw new \InvalidArgumentException('User is not defined, please use setUsername');
        }

        $filter = isset($this->params['user']['filter']) ? $this->params['user']['filter'] : '';

        $entries = $this->ldapConnection->search(
            array(
                'base_dn' => $this->params['user']['base_dn'],
                'filter' => sprintf('(&%s(%s=%s))',
                                $filter,
                                $this->params['user']['mapping']['username'],
                                $this->ldapConnection->escape($this->username)
                )
            )
        );

        if ($entries['count'] > 1) {
            throw new \RuntimeException("This search can only return a single user");
        }

        if ($entries['count'] == 0) {
            throw new UsernameNotFoundException(sprintf('Username "%s" doesn\'t exists', $this->username));
        }

        $this->ldapUser = $entries[0];

        return $this;
    }

    /**
     * @return LdapUserManager $this
     * @throws \RuntimeException
     * @throws \InvalidArgumentException
     * @throws \Sulu\Bundle\LdapBundle\Exception\ConnectionException
     */
    private function addLdapRoles()
    {
        if ($this->ldapUser === null) {
            throw new \RuntimeException('Cannot assign LDAP roles before authenticating user against LDAP');
        }

        $this->ldapUser['roles'] = array();

        if ($this->params['client']['skip_roles'] === true) {
            $this->ldapUser['roles'] = array('ROLE_USER_DEFAULT');

            return $this;
        }

        if (!isset($this->params['role']) && !$this->params['client']['skip_roles']) {
            throw new \InvalidArgumentException("If you want to skip getting the roles, set config option sulu_ldap:client:skip_roles to true");
        }

        $tab = array();

        $filter = isset($this->params['role']['filter']) ? $this->params['role']['filter'] : '';

        $entries = $this->ldapConnection
            ->search(array(
                'base_dn'  => $this->params['role']['base_dn'],
                'filter'   => sprintf('(&%s(%s=%s))',
                                      $filter,
                                      $this->params['role']['user_attribute'],
                                      $this->ldapConnection->escape($this->getUserId())
                ),
                'attrs'    => array(
                    $this->params['role']['name_attribute']
                )
            ));

        for ($i = 0; $i < $entries['count']; $i++) {
            array_push(
                $tab,
                $entries[$i][$this->params['role']['name_attribute']][0]
            );
        }

        $suluRoles = array();
        $mapping = $this->params['role_mapping'];
        foreach ($tab as $ldapRole) {
            $roleName = array_search($ldapRole, $mapping);

            $role = $this->roleRepository->findOneBy(
                array('name' => $roleName)
            );
            $suluRoles[] = $role;
        }

        $this->ldapUser['roles'] = $suluRoles;

        return $this;
    }

    private function bindByDn()
    {
        return $this->ldapConnection->bind($this->ldapUser['dn'], $this->password);
    }

    private function bindByUsername()
    {
        return $this->ldapConnection->bind($this->username, $this->password);
    }

    private function getUserId()
    {
        switch ($this->params['role']['user_id']) {
        case 'dn':
            return $this->ldapUser['dn'];
            break;

        case 'username':
            return $this->username;
            break;

        default:
            throw new \Exception(sprintf("The value can't be retrieved for this user_id : %s",$this->params['role']['user_id']));
        }
    }
}
