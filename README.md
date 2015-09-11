# SuluLdapBundle

## Description
This bundle enables Sulu to authenticate users against a LDAP-server like Active Directory.



## Example Configuration
### config.yml

    sulu_ldap:
        client:
            host: 192.168.70.75
            port: 389
            version: 3 # Optional
    	username: Administrator@sulu.io # Optional
    	password: password # Optional
    	#network_timeout: 10 # Optional
    	#referrals_enabled: true # Optional
    	#bind_username_before: true # Optional
    	#skip_roles: true # Optional
    
        user:
            base_dn: cn=Users,dc=sulu,dc=io
            filter: (objectclass=person) #Optional
            mapping:
                username: sAMAccountName  # maps username to ldap field
                email: mail # maps email to ldap field
                firstname: givenname # maps firstname to ldap field
                lastname: sn # maps lastname to ldap field
                locale: language # maps locale to ldap field (ISO-2 language)
                enabled: useraccountcontrol # maps enabled to ldap field
        role:
            base_dn: cn=Users,dc=sulu,dc=io
            filter: (objectclass=group)
            #filter: (&(objectclass=group)(cn=ldap_groupname)) #Optional
            name_attribute: cn
            user_attribute: member
            user_id: dn
        role-mapping:
            "sulu-ldapauth": ldapauth # maps Sulu role "sulu-ldapauth" to LDAP group ldapauth"

### security.yml

    security:
        access_decision_manager:
            strategy: affirmative
    
        acl:
            connection: default
    
        encoders:
            Sulu\Bundle\LdapBundle\Entity\LdapUserInterface: plaintext
    
        providers:
            ldap:
                id: sulu_ldap.security.user.provider
    
        access_control:
            - { path: ^/login, roles: IS_AUTHENTICATED_ANONYMOUSLY }
            - { path: ^/,      roles: IS_AUTHENTICATED_FULLY }
    
        firewalls:
            website:
                pattern: ^/
                anonymous: ~
                sulu_ldap:
                    check_path: sulu_ldap_login_check
                    login_path: sulu_ldap_login
                    csrf_provider: form.csrf_provider
                    intention: authenticate
                    provider: ldap
                    allowed_roles:  # role name defined in Sulu
                        - sulu_ldapauth
                logout:
                    path: sulu_ldap_logout
                    target: sulu_ldap_login

### security.yml (chaining providers - example for Sulu backend)

    security:
        access_decision_manager:
            strategy: unanimous
            allow_if_all_abstain: true
    
        acl:
            connection: default
    
        encoders:
            Sulu\Bundle\SecurityBundle\Entity\User:
                algorithm: sha512
                iterations: 5000
                encode_as_base64: false
    
        providers:
            multiples:
                chain:
                    providers: [ldap, sulu]
            sulu:
                id: sulu_security.user_repository
            ldap:
                id: sulu_ldap.security.user.provider
    
        access_control:
            - { path: ^/admin/reset, roles: IS_AUTHENTICATED_ANONYMOUSLY }
            - { path: ^/admin/security/reset, roles: IS_AUTHENTICATED_ANONYMOUSLY }
            - { path: ^/admin/login, roles: IS_AUTHENTICATED_ANONYMOUSLY }
            - { path: ^/admin/_wdt, roles: IS_AUTHENTICATED_ANONYMOUSLY }
            - { path: ^/admin, roles: ROLE_USER }
    
        firewalls:
            admin:
                pattern: ^/
                anonymous: ~
                entry_point: sulu_security.authentication_entry_point
                sulu_ldap:
                    provider: multiples
                    allowed_roles:  # role name defined in Sulu
                        - sulu_ldapauth
                form_login:
                    login_path: sulu_admin.login
                    check_path: sulu_admin.login_check
                    success_handler: sulu_security.authentication_handler
                    failure_handler: sulu_security.authentication_handler
                logout:
                    path: /admin/logout
                    target: /admin/
    
    sulu_security:
        checker:
            enabled: true
