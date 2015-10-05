<?php

namespace Sulu\Bundle\LdapBundle\Manager;

use Psr\Log\LoggerInterface;
use Sulu\Bundle\LdapBundle\Exception\ConnectionException;

class LdapConnection implements LdapConnectionInterface
{
    /** @var array */
    private $params;

    /** @var LoggerInterface */
    private $logger;

    /** @var resource */
    protected $ress;

    public function __construct(array $params, LoggerInterface $logger)
    {
        $this->params = $params;
        $this->logger = $logger;
    }

    /**
     * @param array $params
     *
     * @return array|bool
     *
     * @throws ConnectionException
     * @throws \Exception
     */
    public function search(array $params)
    {
        $this->connect();

        $ref = array(
            'base_dn' => '',
            'filter' => '',
        );

        if (count($diff = array_diff_key($ref, $params))) {
            throw new \Exception(sprintf('You must define %s', print_r($diff, true)));
        }

        $attrs = isset($params['attrs']) ? $params['attrs'] : array();

        $this->logger->info(
            sprintf(
                'ldap_search base_dn %s, filter %s',
                print_r($params['base_dn'], true),
                print_r($params['filter'], true)
            )
        );

        $search = @ldap_search(
            $this->ress,
            $params['base_dn'],
            $params['filter'],
            $attrs
        );
        $this->checkLdapError();

        if ($search) {
            $entries = ldap_get_entries($this->ress, $search);

            @ldap_free_result($search);

            return is_array($entries) ? $entries : false;
        }

        return false;
    }

    /**
     * @param $user_dn
     * @param string $password
     * @param null $ress
     *
     * @return bool
     *
     * @throws ConnectionException
     * @throws \Exception
     */
    public function bind($user_dn, $password = '', $ress = null)
    {
        if ($ress === null) {
            if ($this->ress === null) {
                $this->connect($user_dn, $password);
            }

            $ress = $this->ress;
        }

        if (empty($user_dn) || ! is_string($user_dn)) {
            throw new ConnectionException("LDAP user's DN (user_dn) must be provided (as a string).");
        }

        // According to the LDAP RFC 4510-4511, the password can be blank.
        @ldap_bind($ress, $user_dn, $password);
        $this->checkLdapError();

        return true;
    }

    public function getParameters()
    {
        return $this->params;
    }

    public function getHost()
    {
        return $this->params['client']['host'];
    }

    public function getPort()
    {
        return $this->params['client']['port'];
    }

    public function getBaseDn($index)
    {
        return $this->params[$index]['base_dn'];
    }

    public function getFilter($index)
    {
        return $this->params[$index]['filter'];
    }

    public function getNameAttribute($index)
    {
        return $this->params[$index]['username_attribute'];
    }

    public function getUserAttribute($index)
    {
        return $this->params[$index]['user_attribute'];
    }

    private function connect($user_dn = null, $password = null)
    {
        $port = isset($this->params['client']['port']) ? $this->params['client']['port'] : '389';

        $ress = @ldap_connect($this->params['client']['host'], $port);

        if (isset($this->params['client']['version'])) {
            ldap_set_option($ress, LDAP_OPT_PROTOCOL_VERSION, $this->params['client']['version']);
        }

        if (isset($this->params['client']['referrals_enabled'])) {
            ldap_set_option($ress, LDAP_OPT_REFERRALS, $this->params['client']['referrals_enabled']);
        }

        if (isset($this->params['client']['network_timeout'])) {
            ldap_set_option($ress, LDAP_OPT_NETWORK_TIMEOUT, $this->params['client']['network_timeout']);
        }

        if ($user_dn) {
            @ldap_bind($ress, $user_dn, $password);
        } elseif (isset($this->params['client']['username'])) {
            if (!isset($this->params['client']['password'])) {
                throw new \Exception('You must uncomment password key');
            }

            // create RDN for user
            //$dn =  $this->params['user']['mapping']['username'] . '=' . $this->params['client']['username'] . ',' . $this->params['user']['base_dn'];

            @ldap_bind($ress, $this->params['client']['username'], $this->params['client']['password']);
        }
        $this->checkLdapError($ress);

        $this->ress = $ress;

        return $this;
    }

    /**
     * Checks if there were an error during last ldap call
     *
     * @param resource $ress
     *
     * @throws \Sulu\Bundle\LdapBundle\Exception\ConnectionException
     */
    private function checkLdapError($ress = null)
    {
        if (0 != $code = $this->getErrno($ress)) {
            $message = $this->getError($ress);
            $this->logger->error('LDAP returned an error with code ' . $code . ' : ' . $message);
            throw new ConnectionException($message, $code);
        }
    }

    /**
     * @param resource|null $resource
     *
     * @return null|string
     *
     * @see https://wiki.servicenow.com/index.php?title=LDAP_Error_Codes
     */
    public function getErrno($resource = null)
    {
        $resource = $resource ?: $this->ress;
        if (!$resource) {
            return null;
        }

        return ldap_errno($resource);
    }

    /**
     * @param resource|null $resource
     *
     * @return null|string
     */
    public function getError($resource = null)
    {
        $resource = $resource ?: $this->ress;
        if (!$resource) {
            return null;
        }

        return ldap_error($resource);
    }

    /**
     * Escape string for use in LDAP search filter.
     *
     * @link http://www.php.net/manual/de/function.ldap-search.php#90158
     * See RFC2254 for more information.
     * @link http://msdn.microsoft.com/en-us/library/ms675768(VS.85).aspx
     * @link http://www-03.ibm.com/systems/i/software/ldap/underdn.html
     *
     * @param $str
     *
     * @return mixed
     */
    public function escape($str)
    {
        $metaChars = array('*', '(', ')', '\\', chr(0));

        $quotedMetaChars = array();

        foreach ($metaChars as $key => $value) {
            $quotedMetaChars[$key] = '\\'.str_pad(dechex(ord($value)), 2, '0');
        }

        $str = str_replace($metaChars, $quotedMetaChars, $str);

        return ($str);
    }
}
