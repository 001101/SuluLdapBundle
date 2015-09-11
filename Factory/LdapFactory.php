<?php

namespace Sulu\Bundle\LdapBundle\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AbstractFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\Reference;

class LdapFactory extends AbstractFactory
{
    public function __construct()
    {
        $this->addOption('username_parameter', '_username');
        $this->addOption('password_parameter', '_password');
        $this->addOption('csrf_parameter', '_csrf_token');
        $this->addOption('intention', 'ldap_authenticate');
        $this->addOption('post_only', true);
    }

    public function getPosition()
    {
        return 'form';
    }

    public function getKey()
    {
        return 'sulu_ldap';
    }

    /**
     * @param NodeDefinition $node
     */
    public function addConfiguration(NodeDefinition $node)
    {
        parent::addConfiguration($node);
    
        $node
            ->children()
                ->scalarNode('csrf_provider')->cannotBeEmpty()->end()
                ->arrayNode('allowed_roles')->prototype('scalar')->end()
            ->end();

    }

    protected function getListenerId()
    {
        return 'sulu_ldap.security.authentication.listener';
    }

    protected function createAuthProvider(ContainerBuilder $container, $id, $config, $userProviderId)
    {
        $dao = 'security.authentication.provider.dao.'.$id;
        $container
            ->setDefinition($dao, new DefinitionDecorator('security.authentication.provider.dao'))
            ->replaceArgument(0, new Reference($userProviderId))
            ->replaceArgument(2, $id);

        $provider = 'sulu_ldap.security.authentication.provider.'.$id;
        $container
            ->setDefinition($provider, new DefinitionDecorator('sulu_ldap.security.authentication.provider'))
            ->replaceArgument(0, new Reference($userProviderId))
            ->replaceArgument(1, new Reference($dao))
            ->replaceArgument(4, $id)
            ->replaceArgument(6, $config);

        return $provider;
    }

    protected function createlistener($container, $id, $config, $userProvider)
    {
        $listenerId = parent::createListener($container, $id, $config, $userProvider);

        if (isset($config['csrf_provider'])) {
            $container
                ->getDefinition($listenerId)
                ->addArgument(new Reference($config['csrf_provider']));
        }

        return $listenerId;
    }

    protected function createEntryPoint($container, $id, $config, $defaultEntryPoint)
    {
        $entryPointId = 'sulu_ldap.security.authentication.form_entry_point.'.$id;
        $container
            ->setDefinition($entryPointId, new DefinitionDecorator('sulu_ldap.security.authentication.form_entry_point'))
            ->addArgument(new Reference('security.http_utils'))
            ->addArgument($config['login_path'])
            ->addArgument($config['use_forward']);

        return $entryPointId;
    }
}
