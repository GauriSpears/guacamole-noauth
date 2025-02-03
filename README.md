# guacamole-noauth
NoAuth and PostAuth extentions for Guacamole

* NoAuth - updated version of NoAuth extension. Grants *all* users access to all connections from xml config without any need of authentication. Compatible with recent Guacamole versions. Fixed deprecated dependencies.

Previous versions of Guacamole had NoAuth extension: https://guacamole.apache.org/doc/0.9.9/gug/noauth.html but it was removed in 0.9.13: https://github.com/apache/guacamole-client/pull/237 However, in some usage cases it may be useful. Ignores all other authentication requirements, even from plugins with higher priority.

* PostAuth - extension to grant all *authenticated* users access to all connections from xml config. Use with another authentication extension.

Guacamole OpenId Connect extension can't store connection configurations and demands on another extension, i.e. database extension. In case when authentication is performed on OpedId server side and all users need access to the same connections this way looks excessive. That's why this extension has been written. Comparing to NoAuth, I had to use AuthenticationProvider API because SimpleAuthenticationProvider adds GuacamoleConfiguration to UserContext without checking whether user is authenticated or not.

**Configuration:** both extensions by default get connections from noauth-config.xml (see example in doc subfolder) but you can override the path with `noauth-config` and `postauth-config` properties in guacamole.properties

**Build howto:** install maven, then `mvn package` in a directory of required extension.
