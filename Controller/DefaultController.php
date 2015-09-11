<?php

namespace Sulu\Bundle\LdapBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;

class DefaultController extends Controller
{
    public function loginAction(Request $request)
    {
        $authenticationUtils = $this->get('security.authentication_utils');

        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();

        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render(
            'SuluLdapBundle:Default:login.html.twig',
            array(
            // last username entered by the user
            'last_username' => $lastUsername,
            'error'         => $error,
        ));
    }

    public function loginCheckAction($name)
    {
        return $this->render('SuluLdapBundle:Default:index.html.twig');
    }

    public function logoutAction($name)
    {
        return $this->render('SuluLdapBundle:Default:index.html.twig');
    }
}
