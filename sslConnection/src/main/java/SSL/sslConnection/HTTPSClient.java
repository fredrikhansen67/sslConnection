package SSL.sslConnection;


import java.util.ArrayList;
import java.util.List;

import java.net.URL;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;


import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class HTTPSClient {

	private static final Logger logger = LoggerFactory.getLogger(HTTPSClient.class);
	private static List<String> targetURL = new ArrayList<String>();

	
//	static {
//		javax.net.ssl.HttpsURLConnection
//				.setDefaultHostnameVerifier(new javax.net.ssl.HostnameVerifier() {
//
//					public boolean verify(String hostname,
//							javax.net.ssl.SSLSession sslSession) {
//						if (hostname.equals("localhost")) {
//							return true;
//						}
//						return false;
//					}
//				});
//	}

	/**
	 * 
	 */
	public HTTPSClient() {
		logger.debug("default constructor");
	}

	
	
	public static void main(String[] args) {
		targetURL.add("https://github.com/");
		targetURL.add("https://www.skistar.com/sv/");

		for (String httpURL : targetURL) {
			HttpsURLConnection conn = null;
			try {
				// Create connection
				logger.info("Try to connect to the URL " 
						+ httpURL
						+ " ...");
				URL url = new URL(httpURL);
				conn = (HttpsURLConnection) url.openConnection();

				// Prepare a GET request Action
				conn.setRequestMethod("GET");
				conn.setRequestProperty("User-Agent", "Freddans test");
				conn.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml");
				conn.setRequestProperty("Accept-Language", "sv-sv,sv");

				conn.setUseCaches(false);
				conn.setDoOutput(true);

				// Create a SSL SocketFactory
				SSLSocketFactory sslSocketFactory = getFactorySimple();
				conn.setSSLSocketFactory(sslSocketFactory);

				logger.info("HTTP Response Code {}", conn.getResponseCode());
				logger.info("HTTP Response Message {}", conn.getResponseMessage());
				logger.info("HTTP Content Length {}", conn.getContentLength());
				logger.info("HTTP Content Type {}", conn.getContentType());
				logger.info("HTTP Cipher Suite {}", conn.getCipherSuite());
				logger.info("HTTP Headerfield {}", conn.getHeaderField(2));

				
				Certificate[] serverCertificate = conn.getServerCertificates();
				
				for (Certificate certificate : serverCertificate) {
					logger.info("Certificate Type {}", certificate.getType());
					
					if (certificate instanceof X509Certificate) {
				        X509Certificate x509cert = (X509Certificate) certificate;

				        // Get subject
				        Principal principal = x509cert.getSubjectDN();
				        logger.info("Certificate Subject DN {}", principal.getName());

				        // Get issuer
				        principal = x509cert.getIssuerDN();
				        logger.info("Certificate IssuerDn {}", principal.getName());
				      }
				}
				
				// Close Connection
				conn.disconnect();

			} catch (Exception e) {
				if (conn != null) {
					conn.disconnect();
				}
				logger.error(e.getMessage());
			}
		}
	}

	/**
	 *  Gets factory for TLS
	 * @return
	 * @throws Exception
	 */
	private static SSLSocketFactory getFactorySimple() throws Exception {
		SSLContext context = SSLContext.getInstance("TLS");
		context.init(null, null, null);
		return context.getSocketFactory();
	}
}
