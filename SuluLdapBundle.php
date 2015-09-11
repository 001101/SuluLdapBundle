<?php

namespace Sulu\Bundle\LdapBundle;

use Sulu\Bundle\LdapBundle\Factory\LdapFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class SuluLdapBundle extends Bundle
{
    public function boot()
    {
        if (!function_exists('ldap_connect')) {
            throw new \Exception("module php-ldap isn't installed");
        }
    }

    /**
     * Build the bundle.
     *
     * This is used to register the security listener to support Symfony 2.1.
     *
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     */
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new LdapFactory());
    }
}
