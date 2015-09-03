<?php

namespace Sulu\Bundle\LdapBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;

class DefaultController extends Controller
{
    public function indexAction($name)
    {
        return $this->render('SuluLdapBundle:Default:index.html.twig', array('name' => $name));
    }
}
