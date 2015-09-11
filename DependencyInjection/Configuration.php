<?php

namespace Sulu\Bundle\LdapBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * This is the class that validates and merges configuration from your app/config files
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/extension.html#cookbook-bundles-extension-config-class}
 */
class Configuration implements ConfigurationInterface
{
    /**
     * {@inheritdoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('sulu_ldap');
        $rootNode
            ->children()
            ->append($this->addClientNode())
            ->append($this->addUserNode())
            ->append($this->addRoleNode())
            ->append($this->addRoleMappingNode())
            ->end()
        ;

        return $treeBuilder;
    }

    private function addClientNode()
    {
        $treeBuilder = new TreeBuilder();
        $node = $treeBuilder->root('client');

        $node
            ->isRequired()
            ->children()
            ->scalarNode('host')->isRequired()->cannotBeEmpty()->end()
            ->scalarNode('port')->defaultValue(389)->end()
            ->scalarNode('version')->end()
            ->scalarNode('username')->end()
            ->scalarNode('password')->end()
            ->booleanNode('bind_username_before')->defaultFalse()->end()
            ->scalarNode('referrals_enabled')->end()
            ->scalarNode('network_timeout')->end()
            ->booleanNode('skip_roles')->defaultFalse()->end()
            ->end()
        ;

        return $node;
    }

    private function addUserNode()
    {
        $treeBuilder = new TreeBuilder();
        $node = $treeBuilder->root('user');

        $node
            ->isRequired()
            ->children()
            ->scalarNode('base_dn')->isRequired()->cannotBeEmpty()->end()
            ->scalarNode('filter')->end()
            ->variableNode('attributes')->defaultValue(array())->end()
            ->append($this->addUserMappingNode())
            ->end()
        ;

        return $node;
    }

    private function addUserMappingNode()
    {
        $treeBuilder = new TreeBuilder();
        $node = $treeBuilder->root('mapping');

        $node
            ->isRequired()
            ->children()
            ->scalarNode('username')->defaultValue('cn')->end()
            ->scalarNode('email')->defaultValue('email')->end()
            ->scalarNode('firstname')->defaultValue('givenname')->end()
            ->scalarNode('lastname')->defaultValue('sn')->end()
            ->scalarNode('locale')->defaultValue('locale')->end()
            ->scalarNode('enabled')->defaultValue('enabled')->end()
            ->end();

        return $node;
    }

    private function addRoleNode()
    {
        $treeBuilder = new TreeBuilder();
        $node = $treeBuilder->root('role');

        $node
            ->children()
            ->scalarNode('base_dn')->isRequired()->cannotBeEmpty()->end()
            ->scalarNode('filter')->end()
            ->scalarNode('name_attribute')->defaultValue('cn')->end()
            ->scalarNode('user_attribute')->defaultValue('member')->end()
            ->scalarNode('user_id')->defaultValue('dn')
            ->validate()
            ->ifNotInArray(array('dn', 'username'))
            ->thenInvalid('Only dn or username')
            ->end()
            ->end()
            ->end()
        ;

        return $node;
    }

    private function addRoleMappingNode()
    {
        $treeBuilder = new TreeBuilder();
        $node = $treeBuilder->root('role_mapping');

        $node
            ->useAttributeAsKey('interface')
            ->prototype('scalar')
            ->cannotBeEmpty()
            ->end()
        ;

        return $node;
    }
}
