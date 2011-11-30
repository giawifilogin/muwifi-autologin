package net.gnor.giawifilogin;

import java.io.IOException;
import java.net.ConnectException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.protocol.HTTP;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import android.util.Log;

public class MuWifiClient {

	// These are not regex
	static final String LOGIN_SUCCESSFUL_PATTERN = "apc.aptilo.com/apc/showsession.phtml";
	static final String TAG = "MuWifiClient";
	
	static final String FORM_USERNAME = "username";
	static final String FORM_PASSWORD = "password";
	static final String FORM_URL = "https://securelogin.arubanetworks.com/auth/index.html/u";
	static final int CONNECTION_TIMEOUT = 2000;
	static final int SOCKET_TIMEOUT = 2000;
	static final int RETRY_COUNT = 2;
	
	private String mUsername;
	private String mPassword;
	private DefaultHttpClient mHttpClient;
	
	public MuWifiClient(String username, String password) {
		mUsername = username;
		mPassword = password;
		
		mHttpClient = new DefaultHttpClient();
		HttpParams params = mHttpClient.getParams();
		HttpConnectionParams.setConnectionTimeout(params, CONNECTION_TIMEOUT);
		HttpConnectionParams.setSoTimeout(params, SOCKET_TIMEOUT);
		
		// Also retry POST requests (normally not retried because it is not regarded idempotent)
		mHttpClient.setHttpRequestRetryHandler(new HttpRequestRetryHandler() {
			@Override
			public boolean retryRequest(IOException exception, int executionCount,
					HttpContext context) {
		        if (executionCount >= RETRY_COUNT) {
		            // Do not retry if over max retry count
		            return false;
		        }
		        if (exception instanceof UnknownHostException) {
		            // Unknown host
		            return false;
		        }
		        if (exception instanceof ConnectException) {
		            // Connection refused 
		            return false;
		        }
		        if (exception instanceof SSLHandshakeException) {
		            // SSL handshake exception
		            return false;
		        }

		        return true;
			}
		});
	}
	
	public boolean loginRequired() throws IOException {
		try {
			HttpGet httpget = new HttpGet("https://www.google.com/");
			mHttpClient.execute(httpget);
		}
		catch (SSLException e) {
			return true; // If login is required, the certificate sent will be securelogin.arubanetworks.com
		}
		return false;
	}
	
	public void login() throws IOException, LoginException {
		
//		HostnameVerifier hostnameVerifier = org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
//
//        DefaultHttpClient client = new DefaultHttpClient();
//
//        SchemeRegistry registry = new SchemeRegistry();
//        SSLSocketFactory socketFactory = SSLSocketFactory.getSocketFactory();
//        socketFactory.setHostnameVerifier((X509HostnameVerifier) hostnameVerifier);
//        registry.register(new Scheme("https", socketFactory, 443));
//        SingleClientConnManager mgr = new SingleClientConnManager(client.getParams(), registry);
//        DefaultHttpClient httpClient = new DefaultHttpClient(mgr, client.getParams());
//
//        // Set verifier     
//        HttpsURLConnection.setDefaultHostnameVerifier(hostnameVerifier);
//        TrustManager[] trustAllCerts = new TrustManager[]{
//        		new X509TrustManager() {
//        			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
//        				return null;
//        			}
//        			public void checkClientTrusted(
//        					java.security.cert.X509Certificate[] certs, String authType) {
//        			}
//        			public void checkServerTrusted(
//        					java.security.cert.X509Certificate[] certs, String authType) {
//        			}
//        		}
//        };
//
//        // Install the all-trusting trust manager
//        try {
//        	SSLContext sc = SSLContext.getInstance("SSL");
//        	sc.init(null, trustAllCerts, new java.security.SecureRandom());
//        	HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
//        } catch (Exception e) {
//        }
        HttpClient httpClient = this.getNewHttpClient();
        // Example send http request
        String url = "http://apc.aptilo.com/cgi-bin/auto?url=http://www.google.com/";
        HttpGet req = new HttpGet(url);
        HttpResponse response = httpClient.execute(req);
        BufferedReader in = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
        String line;
        StringBuilder html = new StringBuilder();
        while((line = in.readLine()) != null)
        {
            html.append(line);
        }
        in.close();
        Header header = response.getLastHeader("Location");
        HttpPost httppost;
        if (header != null) {
        	url = header.getValue();
        }
        try {
			HtmlForm form = new HtmlForm (new URL(url), html.toString());
			List<NameValuePair> formparams = new ArrayList<NameValuePair>();
			
            // output parameters to request body
            StringBuilder sb = new StringBuilder();
            String value;
            for(Map.Entry<String, String> entry : form.parameters.entrySet())
            {
            	if (entry.getKey().equals(FORM_USERNAME))
            		value = mUsername;
            	else if (entry.getKey().equals(FORM_PASSWORD))
            		value = mPassword;
            	else
            		value = entry.getValue();
            	Log.d(TAG, "entry: " + entry.getKey() + " : " + value);
            	formparams.add(new BasicNameValuePair(entry.getKey(), value));
            }
    		UrlEncodedFormEntity entity = new UrlEncodedFormEntity(formparams, "UTF-8");
    		httppost = new HttpPost(form.actionUrl.toString());
    		httppost.setEntity(entity);
        } catch (InvalidFormException e) {
			throw new LoginException(e.getMessage());
		}
		HttpResponse response2 =  httpClient.execute(httppost);
		String strRes = EntityUtils.toString(response2.getEntity());
		
		if (strRes.contains(LOGIN_SUCCESSFUL_PATTERN)) {
			// login successful
		} else {
			throw new LoginException(strRes);
		}
	}
	public HttpClient getNewHttpClient() {
	    try {
	        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
	        trustStore.load(null, null);

	        SSLSocketFactory sf = new MySSLSocketFactory(trustStore);
	        sf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

	        HttpParams params = new BasicHttpParams();
	        HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
	        HttpProtocolParams.setContentCharset(params, HTTP.UTF_8);

	        SchemeRegistry registry = new SchemeRegistry();
	        registry.register(new Scheme("http", PlainSocketFactory.getSocketFactory(), 80));
	        registry.register(new Scheme("https", sf, 443));

	        ClientConnectionManager ccm = new ThreadSafeClientConnManager(params, registry);
	        return new DefaultHttpClient(ccm, params);
	    } catch (Exception e) {
	        return new DefaultHttpClient();
	    }
	}	
}
