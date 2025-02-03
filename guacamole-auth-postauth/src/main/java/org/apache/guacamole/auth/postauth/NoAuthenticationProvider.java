package org.apache.guacamole.auth.postauth;

import java.util.Map;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.net.auth.simple.SimpleUserContext;
import org.apache.guacamole.net.auth.AbstractAuthenticationProvider;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.properties.FileGuacamoleProperty;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

/**
 * Provide all available GuacamoleConfigurations to users authenticated with  
 * LDAP, OpenId Connect and other extentions. Eliminate the need to install 
 * database extention.
 *
 * GuacamoleConfiguration are read from the XML file defined by `postauth-config`
 * in the Guacamole configuration file (`guacamole.properties`).
 *
 *
 * Example `guacamole.properties`:
 *
 *  postauth-config: /etc/guacamole/noauth-config.xml
 *
 *
 * Example `noauth-config.xml`:
 *
 *  <configs>
 *    <config name="my-rdp-server" protocol="rdp">
 *      <param name="hostname" value="my-rdp-server-hostname" />
 *      <param name="port" value="3389" />
 *    </config>
 *  </configs>
 */
 //We can't use SimpleAuthenticationProvider because it 
public class NoAuthenticationProvider extends AbstractAuthenticationProvider {

    /**
     * Logger for this class.
     */
    private Logger logger = LoggerFactory.getLogger(NoAuthenticationProvider.class);

    /**
     * Map of all known configurations, indexed by identifier.
     */
    private Map<String, GuacamoleConfiguration> configs;

    /**
     * The last time the configuration XML was modified, as milliseconds since
     * UNIX epoch.
     */
    private long configTime;

    /**
     * Guacamole server environment.
     */
    private final Environment environment;
    
    /**
     * The XML file to read the configuration from.
     */
    public static final FileGuacamoleProperty NOAUTH_CONFIG = new FileGuacamoleProperty() {

        @Override
        public String getName() {
            return "postauth-config";
        }

    };

    /**
     * The default filename to use for the configuration, if not defined within
     * guacamole.properties.
     */
    public static final String DEFAULT_NOAUTH_CONFIG = "noauth-config.xml";

    /**
     * Creates a new NoAuthenticationProvider that does not perform any
     * authentication at all. You need to use another extension for authentication.
     *
     * @throws GuacamoleException
     *     If a required property is missing, or an error occurs while parsing
     *     a property.
     */
    public NoAuthenticationProvider() throws GuacamoleException {
        environment = LocalEnvironment.getInstance();
    }

    @Override
    public String getIdentifier() {
        return "postauth";
    }

    /**
     * Retrieves the configuration file, as defined within guacamole.properties.
     *
     * @return The configuration file, as defined within guacamole.properties.
     * @throws GuacamoleException If an error occurs while reading the
     *                            property.
     */
    private File getConfigurationFile() throws GuacamoleException {

        // Get config file, defaulting to GUACAMOLE_HOME/noauth-config.xml
        File configFile = environment.getProperty(NOAUTH_CONFIG);
        if (configFile == null)
            configFile = new File(environment.getGuacamoleHome(), DEFAULT_NOAUTH_CONFIG);

        return configFile;

    }

    public synchronized void init() throws GuacamoleException {

        // Get configuration file
        File configFile = getConfigurationFile();
        logger.debug("Reading configuration file: \"{}\"", configFile);

        // Parse document
        try {

            // Set up parser
            NoAuthConfigContentHandler contentHandler = new NoAuthConfigContentHandler();

            SAXParserFactory parserFactory = SAXParserFactory.newInstance();
            parserFactory.setNamespaceAware(true);
            SAXParser saxparser = parserFactory.newSAXParser();
            XMLReader parser = saxparser.getXMLReader();
            parser.setContentHandler(contentHandler);

            // Read and parse file
            Reader reader = new BufferedReader(new FileReader(configFile));
            parser.parse(new InputSource(reader));
            reader.close();

            // Init configs
            configTime = configFile.lastModified();
            configs = contentHandler.getConfigs();

        }
        catch (IOException e) {
            throw new GuacamoleServerException("Error reading configuration file.", e);
        }
        catch (SAXException e) {
            throw new GuacamoleServerException("Error parsing XML file.", e);
        }
        catch (ParserConfigurationException e) {
            throw new GuacamoleServerException("Error configuring XML parser.", e);
        }

    }
    
    /**
     * Do not allow to authenticate users. If you'd like to grant access to use 
     * all connections without any authentication at all just use noauth extention instead.
     */
    @Override
    public AuthenticatedUser authenticateUser(Credentials credentials)
            throws GuacamoleException {
        return null;
    }
    
    /**
     * Provide all connection configurations.
     */
    @Override
    public UserContext getUserContext(AuthenticatedUser authenticatedUser)
            throws GuacamoleException {
        // Check mapping file mod time
        File configFile = getConfigurationFile();
        if (configFile.exists() && configTime < configFile.lastModified()) {

            // If modified recently, gain exclusive access and recheck
            synchronized (this) {
                if (configFile.exists() && configTime < configFile.lastModified()) {
                    logger.debug("Configuration file \"{}\" has been modified.", configFile);
                    init(); // If still not up to date, re-init
                }
            }

        }

        // If no mapping available, report as such
        if (configs == null)
            throw new GuacamoleServerException("Configuration could not be read.");

        //authenticatedUser.getIdentifier() is not common member of AuthenticatedUser 
        //and may be null, but it is the only way for OpenID and other extensions
        return new SimpleUserContext(this, authenticatedUser.getIdentifier(), configs);    
        
    }

    @Override
    public UserContext updateUserContext(UserContext context,
            AuthenticatedUser authenticatedUser, Credentials credentials)
            throws GuacamoleException {
        return context;
    }
}
