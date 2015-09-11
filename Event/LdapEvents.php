<?php

namespace Sulu\Bundle\LdapBundle\Event;

final class LdapEvents
{
    const PRE_BIND = 'sulu_ldap.security.authentication.pre_bind';
    const POST_BIND = 'sulu_ldap.security.authentication.post_bind';
}
