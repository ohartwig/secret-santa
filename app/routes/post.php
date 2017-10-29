<?php

use Symfony\Component\HttpFoundation\Request;

$app->post('/signup', function (Request $request) use ($app) {
    if (strlen($request->request->get('user_login')) < 3) {
        $app['session']->getFlashBag()->add('message', array(
            'type' => 'danger', 
            'content' => 'Ihre Login-ID muss mindestens 3 Zeichen lang sein.'
        ));
        return $app->redirect($app['url_generator']->generate('signup_get'));
    }

    if (strlen($request->request->get('user_password')) < 4) {
        $app['session']->getFlashBag()->add('message', array(
            'type' => 'danger', 
            'content' => 'Ihr Passwort muss mindestens 5 Zeichen lang sein. Wir empfehlen die Verwendung eines Passworts aus Buchstaben, Groß- und Kleinbuchstaben sowie numerischen Zeichen und Symbolen.'
        ));
        return $app->redirect($app['url_generator']->generate('signup_get'));
    }

    if ($request->request->get('user_password') !== $request->request->get('user_password_verification')) {
        $app['session']->getFlashBag()->add('message', array('type' => 'danger', 'content' => 'Die beiden Passwörter stimmen nicht überein.'));
        return $app->redirect($app['url_generator']->generate('signup_get'));
    }

    if ($app['dao.user']->userLoginExist($request->request->get('user_login'))) {
        $app['session']->getFlashBag()->add('message', array('type' => 'danger', 'content' => "Diese Name " . $request->request->get('username') . " wird schon verwendet"));
        return $app->redirect($app['url_generator']->generate('signup_get'));
    }

    // If the creation of the user is the first one, this user is an admin
    $userAccess = ($app['dao.user']->getNbUsers() === 0) ? "ADMIN" : "USER";

    $app['dao.user']->setUser(
        htmlspecialchars($request->request->get('user_login')),
        $request->request->get('user_password'),
        htmlspecialchars($request->request->get('user_firstname')),
        htmlspecialchars($request->request->get('user_lastname')),
        htmlspecialchars($request->request->get('user_email')),
        $userAccess
    );

    $user = $app['dao.user']->findByUserLogin($request->request->get('user_login'));

    $app['session']->clear();

    $app['session']->set('user', $user);
    $app['session']->set('connected', array('connected' => true));
    $app['session']->getFlashBag()->add('message',
        array(
            'type' => 'success',
            'content' => "Ihr Konto wurde erstellt, Sie sind jetzt mit der App verbunden."
        )
    );

    return $app->redirect($app['url_generator']->generate('index'));
})->bind('signup_post');

$app->post('/login', function (Request $request) use ($app) {
    $app['session']->clear();
    if ($app['dao.user']->verifyLogin($request->request->get('user_login'), $request->request->get('user_password'))) {
        $user = $app['dao.user']->findByUserLogin($request->request->get('user_login'));
        $app['session']->set('user', $user);
        $app['session']->set('connected', array('connected' => true));
        $app['session']->getFlashBag()->add('message',
            array(
                'type' => 'success',
                'content' => 'Erfolgreiche Verbindung'
            )
        );
        return $app->redirect($app['url_generator']->generate('index'));
    } else {
        $app['session']->getFlashBag()->add('message',
            array(
                'type' => 'danger',
                'content' => 'Schlechte Kombination von Bezeichnern.'
            )
        );
        return $app->redirect($app['url_generator']->generate('login_get'));
    }
})->bind('login_post');

$app->post('/administration/new/instance', function(Request $request) use ($app) {
    if (!$app['function.connectedUserIsAdmin']) {
        $app['session']->getFlashBag()->add(
            'message',
            array(
                'type' => 'warning',
                'content' => 'Sie haben keine ausreichenden Zugriffsrechte, um auf dieses Teil zuzugreifen'
            )
        );
        return $app->redirect($app['url_generator']->generate('login_get'));
    }

    $instance_year = date('Y');

    if (strlen($request->request->get('instance_name')) <= 3) {
        $app['session']->getFlashBag()->add(
            'message',
            array(
                'type' => 'warning',
                'content' => 'Instanzname muss aus mehr als 3 Zeichen bestehen'
            )
        );
        return $app->redirect($app['url_generator']->generate('administration'));
    } else {
        $instance_name = htmlspecialchars($request->request->get('instance_name'));
    }

    if ($app['dao.instance']->instanceNameExist($instance_name)) {
        $app['session']->getFlashBag()->add(
            'message',
            array(
                'type' => 'danger',
                'content' => 'Eine Instanz dieses Namens existiert bereits'
            )
        );
        return $app->redirect($app['url_generator']->generate('administration'));
    }

    $instance_hash = hash('md5', $instance_year . htmlspecialchars($instance_name));
    $instance_author = $app['session']->get('user')->getUserId();

    $app['dao.instance']->setInstance($instance_year, $instance_name, $instance_hash, $instance_author);
    $app['session']->getFlashBag()->add('message',
        array(
            'type' => 'success',
            'content' => 'Ihre Instanz ' . $instance_name . ' ' . $instance_hash . ' wurde erstellt'
        )
    );
    return $app->redirect($app['url_generator']->generate('index'));
})->bind('administration_new_instance_post');

$app->post('/instance/join', function(Request $request) use ($app) {
    if (null === $user = $app['session']->get('user')) {
        $app['session']->getFlashBag()->add(
            'message',
            array(
                'type' => 'danger',
                'content' => 'Sie haben keine ausreichenden Zugriffsrechte, um auf dieses Teil zuzugreifen'
            )
        );
        return $app->redirect($app['url_generator']->generate('login_get'));
    }

    $instance_hash = $request->get('instance_hash');

    try {
        $instance = $app['dao.instance']->findInstanceHash($instance_hash);
    } catch (Exception $e) {
        $app['session']->getFlashBag()->add(
            'message',
            array(
                'type' => 'danger',
                'content' => 'Diese Instanz existiert nicht.'
            )
        );
        return $app->redirect($app['url_generator']->generate('index'));
    }

    $instance_id = $instance->getInstanceId();
    $user_id = $user->getUserId();

    if ($app['dao.participation']->participationExist($instance_id, $user_id)) {
        $app['session']->getFlashBag()->add(
            'message',
            array(
                'type' => 'warning',
                'content' => 'Sie sind dieser Instanz bereits beigetreten.'
            )
        );
        return $app->redirect($app['url_generator']->generate('index'));
    }

    $app['dao.participation']->setParticipation($instance_id, $user_id);

    $app['session']->getFlashBag()->add(
        'message',
        array(
            'type' => 'success',
            'content' => 'Sie haben sich der Instanz angeschlossen ' . $instance->getInstanceName()
        )
    );
    return $app->redirect($app['url_generator']->generate('index'));
})->bind('instance_join');

$app->post('/modify/user/{id}', function(Request $request, $id) use ($app) {
    // If the user is not connected, then there is a redirection with a message
    if (null === $user = $app['session']->get('user')) {
        $app['session']->getFlashBag()->add(
            'message',
            array(
                'type' => 'danger',
                'content' => 'Sie haben keine ausreichenden Zugriffsrechte, um auf dieses Teil zuzugreifen'
            )
        );
        return $app->redirect($app['url_generator']->generate('login_get'));
    }

    // If the user is an admin, we find the user with the id from the route
    $user = $app['dao.user']->find($id);

    // If the password is correctly set, then we update it
    if (strlen($request->request->get('user_password')) != 0 && strlen($request->request->get
        ('user_password_verification')) != 0) {
        if (strlen($request->request->get('user_password')) < 4) {
            $app['session']->getFlashBag()->add('message',
                array(
                    'type' => 'danger',
                    'content' => 'Ihr Passwort muss mindestens 5 Zeichen lang sein. Wir empfehlen die Verwendung eines Passworts aus Buchstaben, Groß- und Kleinbuchstaben sowie numerischen Zeichen und Symbolen.'
                )
            );
            return $app->redirect($app['url_generator']->generate('edit_user_id', array('id' => $user->getUserId())));
        }

        if ($request->request->get('user_password') !== $request->request->get('user_password_verification')) {
            $app['session']->getFlashBag()->add('message',
                array(
                    'type' => 'danger',
                    'content' => 'Die beiden Passwörter stimmen nicht überein.'
                )
            );
            return $app->redirect($app['url_generator']->generate('edit_user_id', array('id' => $user->getUserId())));
        }

        $app['dao.user']->updatePassword($request->request->get('user_password'), $user->getUserId());
    }

    if ($app['function.connectedUserIsAdmin'] || $user->getUserId() === $app['session']->get('user')->getUserId()) {
        $app['dao.user']->updateUser(
            $user->getUserId(),
            htmlspecialchars($request->request->get('user_firstname')),
            htmlspecialchars($request->request->get('user_lastname')),
            htmlspecialchars($request->request->get('user_email')),
            $user->getUserAccess()
        );
    }
    
    $user = $app['dao.user']->findByUserLogin($app['session']->get('user')->getUserLogin());
    $app['session']->clear();

    $app['session']->set('user', $user);
    $app['session']->set('connected', array('connected' => true));
    $app['session']->getFlashBag()->add('message',
        array(
            'type' => 'success',
            'content' => "Parameter wurden gespeichert"
        )
    );

    return $app->redirect($app['url_generator']->generate('index'));
})->bind('edit_user_post_id')->assert('id', '\d+');
