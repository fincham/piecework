# piecework

## What is this?

This demo combines both [osquery-controller](https://github.com/fincham/osquery-controller) and [advisory-feeds](https://github.com/fincham/advisory-feeds) to show a realtime feed of what packages are vulnerable to a security advisory on a set of osquery nodes.

![Screenshot](https://i.imgur.com/YK9bjD6.png)

## How do I set it up?

`python-apt` isn't installable easily from pip (it has silent deps on things which are not in PyPi), so you may need to:

    ln -s /usr/lib/python3/dist-packages/apt* $VIRTUAL_ENV/lib/python*/site-packages
    
And install the `python-apt` package outside of the virtualenv.

Once the application is working you'll want to run `manage.py updateadvisories` periodically to update your database. Probably once every 24 hours is sufficient and shouldn't place undue burden on the upstream information sources.

You'll need to set a few values in `settings.py` then deploy the demo as you usually would for Django (for instance, you might like to use a WSGI server such as `waitress`). Most importantly the database connection (sqlite is fine), and the `OSQUERY_ENROLL_SECRET` settings will need to be changed.

### HTTPS in development

`osqueryd` likes to talk to an HTTPS endpoint. The normal `python manage.py runserver` development server in Django doesn't do HTTPS.

The easiest way to resolve this is to use something like `stunnel` to proxy incoming HTTPS connections back to the Django development server.

An example `stunnel` configuration to do this:

    cert = test_server.pem
    key = test_server.key
    foreground = yes
    pid = /tmp/hotplate-hosts-stunnel-dev.pid

    [api]
    accept = localhost:4433
    connect = 8000

`stunnel` can then be launched from the directory where the configuration is kept, e.g. by running `stunnel ./stunnel.conf`

Once `stunnel` is runnning then `osqueryd` may connect to `localhost` on port `4433`.
