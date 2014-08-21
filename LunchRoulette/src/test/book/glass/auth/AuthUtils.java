package test.book.glass.auth;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.StoredCredential;
import com.google.api.client.extensions.appengine.datastore.AppEngineDataStoreFactory;
import com.google.api.client.extensions.appengine.http.UrlFetchTransport;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.DataStore;

public final class AuthUtils
{
  public static final List<String> SCOPES = Arrays.asList(
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/glass.timeline"
  );
  public static final String OAUTH2_PATH = "/oauth2callback";
  private static final Logger LOG = Logger.getLogger(AuthUtils.class.getSimpleName());

  // setup ids
  public static final String WEB_CLIENT_ID;
  public static final String WEB_CLIENT_SECRET;
  public static final String API_KEY;
  static {
    URL resource = AuthUtils.class.getResource("/oauth.properties");
    File propertiesFile = new File("./src/oauth.properties");
    try {
      propertiesFile = new File(resource.toURI());
      LOG.info("Able to find oauth properties from file.");
    } catch (URISyntaxException e) {
      LOG.info(e.toString());
      LOG.info("Using default source path.");
    }
    Properties authProperties = null;
    try {
      FileInputStream authPropertiesStream = new FileInputStream(propertiesFile);
      authProperties = new Properties();
      authProperties.load(authPropertiesStream);
    } catch(IOException e) {
      e.printStackTrace();
    }
    WEB_CLIENT_ID = authProperties.getProperty("client_id");
    WEB_CLIENT_SECRET = authProperties.getProperty("client_secret");
    API_KEY = authProperties.getProperty("api_key");
  }

  public static Credential getCredential(String userId) throws IOException {
    return userId == null ? null : buildCodeFlow().loadCredential( userId );
  }

  public static void deleteCredential(String userId) throws IOException {
    getDataStore().delete( userId );
  }

  public static boolean hasAccessToken(String userId) {
    try {
      Credential cred = getCredential(userId);
      return (cred != null && cred.getAccessToken() != null);
    } catch (IOException e) {
      return false;
    }
  }

  public static DataStore<StoredCredential> getDataStore()
    throws IOException
  {
    AppEngineDataStoreFactory factory = AppEngineDataStoreFactory.getDefaultInstance();
    return StoredCredential.getDefaultDataStore( factory );
  }

  /**
   * Gets the credentials stored in GAE. If expired, uses the refresh token to
   * get a new access token from OAuth
   * @return
   * @throws IOException
   */
// START:flow
  public static AuthorizationCodeFlow buildCodeFlow()
      throws IOException
  {
    return new GoogleAuthorizationCodeFlow.Builder(
        new UrlFetchTransport(),
        new JacksonFactory(),
        WEB_CLIENT_ID,
        WEB_CLIENT_SECRET,
        SCOPES)
    .setApprovalPrompt( "force" )
    .setAccessType("offline")
    .setCredentialDataStore( getDataStore() )
    .build();
  }
// END:flow
  
  public static String fullUrl( HttpServletRequest req, String rawPath )
  {
    GenericUrl url = new GenericUrl( new String(req.getRequestURL()) );
    url.setRawPath( rawPath );
    return url.build();
  }
}
