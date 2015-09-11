<?php

namespace Sulu\Bundle\LdapBundle\Manager;

use Psr\Log\LoggerInterface;

interface LdapConnectionInterface
{
    function __construct(array $params, LoggerInterface $logger);
    function search(array $params);
    function bind($user_dn, $password);
    function getParameters();
    function getHost();
    function getPort();
    function getBaseDn($index);
    function getFilter($index);
    function getNameAttribute($index);
    function getUserAttribute($index);
    function getErrno($resource = null);
    function getError($resource = null);
    function escape($username);
}
