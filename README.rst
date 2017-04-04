Touchstone Integration with Django
==================================

These notes are from trying to set up a Django_ application to work with MIT's
Touchstone_ system, which is an implementation of Shibboleth_. This is a long,
involved process, and I haven't yet gotten it to be fully functional!
This assumes that you are running on a vanilla Debian server -- my test box
has a DNS entry of ``django-shibboleth-demo.odl.mit.edu``.

Here are the steps at a high level:

1. Compile & install nginx with Shibboleth integration
2. Create a vanilla Django project
3. Run Django project with nginx through uWSGI
4. Set up HTTPS with Let's Encrypt
5. Install Shibboleth SP and run as daemon through Supervisor
6. Configure routes in Shibboleth
7. Customize Django project to pick up Shibboleth headers

NGINX
-----

It would be great if we could install nginx_ from the APT package repository,
but unfortunately it's not that simple. We need to add the
`nginx-http-shibboleth`_ module to nginx, and the documentation for that module
suggests adding the `headers-more-nginx-module`_ as well, so that we can
avoid having malicious users spoof headers to Shibboleth. Nginx does have limited
support for dynamic modules, but for various reasons we can't go this route,
so we'll have to compile nginx from source and add these modules into the mix.

.. code-block:: bash

    sudo apt-get install git build-essential libpcre3-dev zlib1g-dev libssl-dev libgeoip-dev
    mkdir nginx-compile && cd nginx-compile
    git clone https://github.com/nginx/nginx.git -b release-1.11.12
    git clone https://github.com/nginx-shib/nginx-http-shibboleth.git
    git clone https://github.com/openresty/headers-more-nginx-module.git
    cd nginx
    ./auto/configure --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf --pid-path=/run/nginx.pid --add-module=../nginx-http-shibboleth/ --add-module=../headers-more-nginx-module/ --with-pcre --with-http_ssl_module --with-http_stub_status_module --with-http_geoip_module --with-http_auth_request_module --with-http_gzip_static_module --with-http_v2_module --with-http_realip_module --with-http_sub_module
    make
    sudo make install
    sudo cp ../nginx-http-shibboleth/includes/* /etc/nginx/

Note that this will install nginx at version 1.11.12. If a more recent version
of nginx is available, you should modify the ``git clone`` line to grab that
release.

Nginx is now installed, but we're not done. When you install nginx via APT, it
also takes care of some additional housekeeping to make it play nicely with
the rest of the computer. Since we're installing it from source, we need to
do that housekeeping ourselves.

First, create a new user for nginx to run under, and make a few new directories:

.. code-block:: bash

    sudo useradd --home-dir /etc/nginx nginx
    sudo mkdir /var/log/nginx
    sudo mkdir /etc/nginx/conf.d

Next, edit nginx's config file at ``/etc/nginx/nginx.conf``. Set these lines
at the top of the file:

.. code-block:: nginx

    user       nginx;
    error_log  /var/log/nginx/error.log;
    pid        /run/nginx.pid;

In the same config file, there is an ``http`` section. At the bottom of that
file, just before the closing brace of this section, add the line
``include conf.d/*.conf;``.

It would also be nice to integrate nginx with systemd_, so that nginx would
be automatically launched when the computer boots up. At a coworker's
suggestion, I've copied over the file that APT's packaged nginx uses
to integrate it with systemd. Create a new file
at ``/etc/systemd/system/multi-user.target.wants/nginx.service`` with this
content:

.. code-block::

    [Unit]
    Description=A high performance web server and a reverse proxy server
    After=network.target

    [Service]
    Type=forking
    PIDFile=/run/nginx.pid
    ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'
    ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'
    ExecReload=/usr/sbin/nginx -g 'daemon on; master_process on;' -s reload
    ExecStop=-/sbin/start-stop-daemon --quiet --stop --retry QUIT/5 --pidfile /run/nginx.pid
    TimeoutStopSec=5
    KillMode=mixed

    [Install]
    WantedBy=multi-user.target

Then run:

.. code-block:: bash

    sudo systemctl daemon-reload
    sudo systemctl enable nginx

*Theoretically*, this should work. In practice, it doesn't, for some reason.
I ended up starting and stopping nginx by running the ``ExecStart`` command
manually.

Django
------

Next, we need a Django_ application. For now, this is pretty vanilla.

.. code-block:: bash

    sudo apt-get install python3-venv
    python3 -m venv venv
    source venv/bin/activate
    pip install django
    django-admin startproject testproject
    cd testproject
    django-admin startapp testapp

Then, install the app into the ``settings.py`` file, create a view
in the app's ``views.py`` file, hook it up to the project ``urls.py`` file, and
try running the project with ``manage.py runserver``. Also add the correct host
URL to the ``ALLOWED_HOSTS`` list in ``settings.py``.

uWSGI
-----

To make nginx run your Django application, we need to use uwsgi_.
There is a ``uwsgi`` package available from the apt-get system, but it doesn't
seem to work the way we want, and `the official docs recommend installing with
pip, instead
<https://uwsgi-docs.readthedocs.io/en/latest/WSGIquickstart.html#installing-uwsgi-with-python-support>`_.
Activate the virtualenv, then:

.. code-block:: bash

    sudo apt-get install python3-dev
    pip install uwsgi
    uwsgi --module=testproject.wsgi:application --env DJANGO_SETTINGS_MODULE=testproject.settings --socket=127.0.0.1:29000 --daemonize=uwsgi.log --pidfile=uwsgi.pid

Port 29000 is arbitrary; use whatever port you want. To test that it's working,
you can do this:

.. code-block:: bash

    pip install uwsgi-tools
    uwsgi_curl 127.0.0.1:29000

and verify that you get the output you expect from your site.

Next, make sure that the ``nginx.conf`` is reading files in the ``conf.d`` directory,
and create this file at ``/etc/nginx/conf.d/django.conf``:

.. code-block:: nginx

    upstream django {
        server 127.0.0.1:29000;
    }

    server {
        listen 80;
        server_name django-shibboleth-demo.odl.mit.edu;
        root /var/www/shibdemo;

        location / {
            uwsgi_pass django;
            include /etc/nginx/uwsgi_params;
        }

        location /static/  {
            alias /var/www/shibdemo/static/;
        }

        location /.well-known/  {
            alias /var/www/shibdemo/.well-known/;
        }
    }

Also edit the file ``/etc/nginx/uwsgi_params`` and add the following lines to
it:

.. code-block:: nginx

    uwsgi_param Host $host;
    uwsgi_param X-Real-IP $remote_addr;
    uwsgi_param X-Forwarded-For $proxy_add_x_forwarded_for;
    uwsgi_param X-Forwarded-Proto $http_x_forwarded_proto;

Make sure that ``/var/www/shibdemo`` exists, and then tell nginx to reload
its configuration. You can run this command to test that everything is working:

.. code-block:: bash

    curl localhost -H "Host: django-shibboleth-demo.odl.mit.edu"


Let's Encrypt
-------------
Shibboleth needs HTTPS to work, and the best way to get that is with
`Let's Encrypt`_.

.. code-block:: bash

    sudo apt-get install certbot -t jessie-backports
    sudo certbot certonly --webroot -w /var/www/shibdemo -d django-shibboleth-demo.odl.mit.edu


You should now have a certificate in the
``/etc/letsencrypt/live/django-shibboleth-demo.odl.mit.edu/`` directory.
Next, we need to tell nginx about it. Add another server block to the
`/etc/nginx/conf.d/django.conf` file that looks like this:

.. code-block:: nginx

    server {
        listen 443 ssl;
        server_name django-shibboleth-demo.odl.mit.edu;
        root /var/www/shibdemo;
        ssl_certificate /etc/letsencrypt/live/django-shibboleth-demo.odl.mit.edu/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/django-shibboleth-demo.odl.mit.edu/privkey.pem;

        location / {
            uwsgi_pass django;
            include /etc/nginx/uwsgi_params;
        }

        location /static/  {
            alias /var/www/shibdemo/static/;
        }

        location /.well-known/  {
            alias /var/www/shibdemo/.well-known/;
        }
    }

The only difference is the ``listen`` line, and adding the ``ssl_certificate`` and
``ssl_certificate_key`` lines. Reload nginx again, and your site should be working
over HTTPS!

Last, we need to disable insecure HTTP and redirect all requests to HTTPS.
To do that, replace the first server block in the
``/etc/nginx/conf.d/django.conf`` file (the one that configures it for
insecure HTTP) with this server block, instead:

.. code-block:: nginx

    server {
        listen 80;
        server_name django-shibboleth-demo.odl.mit.edu;
        return 301 https://$server_name$request_uri;
    }

Reload nginx again, and test that HTTP requests are redirected to HTTPS.

Shibboleth SP
-------------

.. code-block:: bash

    sudo apt-get install shibboleth-sp2-common shibboleth-sp2-utils supervisor
    cd /etc/shibboleth
    sudo wget -N http://web.mit.edu/touchstone/config/shibboleth2-sp/2.5/gen-shib2.sh
    sudo sh gen-shib2.sh

Next, we need to set up Shibboleth SP as a backend for a FastCGI process.
Create the following file at ``/etc/supervisor/conf.d/shibboleth-fastcgi.conf``:

.. code-block:: ini

    [fcgi-program:shibauthorizer]
    command=/usr/lib/x86_64-linux-gnu/shibboleth/shibauthorizer
    socket=unix:///run/shibboleth/shibauthorizer.sock
    socket_owner=_shibd:nginx
    socket_mode=0660
    user=_shibd
    stdout_logfile=/var/log/supervisor/shibauthorizer.log
    stderr_logfile=/var/log/supervisor/shibauthorizer.error.log

    [fcgi-program:shibresponder]
    command=/usr/lib/x86_64-linux-gnu/shibboleth/shibresponder
    socket=unix:///run/shibboleth/shibresponder.sock
    socket_owner=_shibd:nginx
    socket_mode=0660
    user=_shibd
    stdout_logfile=/var/log/supervisor/shibresponder.log
    stderr_logfile=/var/log/supervisor/shibresponder.error.log

The socket locations (``/run/shibboleth/shibauthorizer.sock`` and
``/run/shibboleth/shibresponder.sock``) are arbitrary; use whatever locations
you want.

The restart Supervisor with this command: ``sudo systemctl restart supervisor.service``.
If it doesn't work, try running ``sudo unlink /var/run/supervisor.sock`` first.
Verify that it's working by checking to see if the
``/run/shibboleth/shibauthorizer.sock`` and ``/run/shibboleth/shibresponder.sock``
sockets exist.

Next, we need to connect nginx to Shibboleth via these sockets. First, create
the file ``/etc/nginx/shib_mit_params`` with the following contents:

.. code-block:: nginx

    shib_request_set $shib_remote_user $upstream_http_variable_remote_user;
    uwsgi_param REMOTE_USER $shib_remote_user;
    shib_request_set $shib_eppn $upstream_http_variable_eppn;
    uwsgi_param EPPN $shib_eppn;
    shib_request_set $shib_mail $upstream_http_variable_mail;
    uwsgi_param MAIL $shib_mail;
    shib_request_set $shib_displayname $upstream_http_variable_displayname;
    uwsgi_param DISPLAY_NAME $shib_displayname;

This instructs nginx to grab headers from the Shibboleth authorizer response
and send them to Django, so that Django knows who the user is. Then add
the following sections to your ``/etc/nginx/conf.d/django.conf`` file,
*inside* of the server block:

.. code-block:: nginx

    # FastCGI authorizer for Auth Request module
    location = /shibauthorizer {
        internal;
        include fastcgi_params;
        fastcgi_pass unix:/run/shibboleth/shibauthorizer.sock;
    }

    # FastCGI responder
    location /Shibboleth.sso {
        include fastcgi_params;
        fastcgi_pass unix:/run/shibboleth/shibresponder.sock;
    }

    # A secured location.  Here all incoming requests query the
    # FastCGI authorizer.  Watch out for performance issues and spoofing.
    location /secure {
        include shib_clear_headers;
        shib_request /shibauthorizer;
        shib_request_use_headers on;
        include shib_mit_params;
        uwsgi_pass django;
        include /etc/nginx/uwsgi_params;
    }

Reload nginx again, and verify that you can visit
``https://django-shibboleth-demo.odl.mit.edu/Shibboleth.sso/Metadata``
and get content from Shibboleth SP.

Next, you'll need to send an email to ``touchstone-support@mit.edu`` to get your
client registered in MIT's Touchstone identity provider (IdP). Include the
contents of ``/etc/shibboleth/sp-cert.pem`` in your email.

Configure routes in Shibboleth
------------------------------
We've now configured nginx to know which routes are secured by Shibboleth,
but Shibboleth needs to know that information, too. We're gonna edit some
XML files by hand!

Open the ``/etc/shibboleth/shibboleth2.xml`` file that was generated by MIT's
``gen-shib2.sh`` script. The top-level element should be ``<SPConfig>``, with
an ``<ApplicationDefaults>`` element nested underneath it. Create a new
``<RequestMapper>`` element that is a child of ``<SPConfig>`` and a sibling
of ``<ApplicationDefaults>``. The element should look like this:

.. code-block:: xml

    <RequestMapper type="Native">
      <RequestMap>
        <Host name="django-shibboleth-demo.odl.mit.edu">
          <Path name="secure" authType="shibboleth" requireSession="true" />
        </Host>
      </RequestMap>
    </RequestMapper>

`This RequestMapper is documented on the Shibboleth wiki.
<https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPRequestMapper>`_

Installing Shibboleth from APT also set up the ``shibd`` daemon, which now
needs to be restarted to pick up the new configuration. We'll also need to
restart Supervisor, so that the ``shibauthorizer`` and ``shibresponder``
processes pick up the new configuration, as well. After you've edited the ``shibboleth2.xml`` file, run these commands:

.. code-block:: bash

    sudo service shibd restart
    sudo service supervisor restart

Configure Django with Shibboleth headers
----------------------------------------

We need to enable authentication using the ``REMOTE_USER`` enviornment variable
from nginx.
Django's docs for how to do so are here:
https://docs.djangoproject.com/en/1.10/howto/auth-remote-user/
But we can go through it here, as well.

Activate your virtualenv, and install the `django-shibboleth-remoteuser`_
library:

.. code-block:: bash

    pip install git+https://github.com/Brown-University-Library/django-shibboleth-remoteuser.git

Next, open the ``settings.py`` file, and add the following variables to it:

.. code-block:: python

    SHIBBOLETH_ATTRIBUTE_MAP = {
        "EPPN": (True, "username"),
        "MAIL": (True, "email"),
        # full name is in the "DISPLAY_NAME" header,
        # but no way to parse that into first_name and last_name...
    }
    AUTHENTICATION_BACKENDS = [
        'shibboleth.backends.ShibbolethRemoteUserBackend',
    ]

Also, add the ``ShibbolethRemoteUserMiddleware`` to the ``MIDDLEWARE`` list,
*after* the Django's ``AuthenticationMiddleware``:

.. code-block:: python

    MIDDLEWARE = [
        ...
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'shibboleth.middleware.ShibbolethRemoteUserMiddleware',
        ...
    ]

You might want to use the following template for testing purposes:

.. code-block:: django

    <h1>Touchstone test</h1>
    {% if user.is_authenticated %}
      <p>You are logged in as {{ user.username }}, ID {{ user.id }}</p>
    {% else %}
      <p><a href="/Shibboleth.sso/Login">Login with Touchstone</a></p>
    {% endif %}
    <p><a href="/Shibboleth.sso/Session">Shibboleth session info</a></p>

In order to see your changes, you'll need to restart uWSGI:

.. code-block:: bash

    # activate your virtualenv, then
    uwsgi --reload=uwsgi.pid
    uwsgi --module=testproject.wsgi:application --env DJANGO_SETTINGS_MODULE=testproject.settings --socket=127.0.0.1:29000 --daemonize=uwsgi.log --pidfile=uwsgi.pid

Finished
--------

You now have a Django project running behind nginx that works with Shibboleth.
Congratulations!

.. _Django: https://www.djangoproject.com/
.. _Touchstone: https://ist.mit.edu/touchstone
.. _Shibboleth: https://shibboleth.net
.. _nginx: http://nginx.org/en/docs/
.. _nginx-http-shibboleth: https://github.com/nginx-shib/nginx-http-shibboleth
.. _headers-more-nginx-module: https://github.com/openresty/headers-more-nginx-module
.. _systemd: https://www.freedesktop.org/wiki/Software/systemd/
.. _uwsgi: https://uwsgi-docs.readthedocs.io/en/latest/
.. _Let's Encrypt: https://letsencrypt.org/
.. _django-shibboleth-remoteuser: https://github.com/Brown-University-Library/django-shibboleth-remoteuser
