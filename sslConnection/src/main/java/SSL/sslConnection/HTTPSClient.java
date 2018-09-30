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
	private static List<String> URLdestination = new ArrayList<String>();



	/**
	 * default constructor
	 */
	public HTTPSClient() {
		logger.debug("HTTPSClient Instance created");
	}

	
	
	public static void main(String[] args) {
		URLdestination.add("https://github.com/");
		URLdestination.add("https://www.skistar.com/sv/");

		for (String httpURL : URLdestination) {
			HttpsURLConnection conn = null;
			try {
				// Create connection
				logger.info("Connecting to " 	+ httpURL);
				URL url = new URL(httpURL);
				conn = (HttpsURLConnection) url.openConnection();

				// Prepare the GET request 
				conn.setRequestMethod("GET");
				conn.setRequestProperty("User-Agent", "Freddans test");
				conn.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml");
				conn.setRequestProperty("Accept-Language", "sv-sv,sv");

				conn.setUseCaches(false);
				conn.setDoOutput(true);

				// Create the SSL SocketFactory
				SSLSocketFactory sslSocketFactory = getFactorySimple();
				conn.setSSLSocketFactory(sslSocketFactory);

				logger.info("HTTP Response Code {}", conn.getResponseCode());
				logger.info("HTTP Response Message {}", conn.getResponseMessage());
				logger.info("HTTP Content Length {}", conn.getContentLength());
				logger.info("HTTP Content Type {}", conn.getContentType());
				logger.info("HTTP Cipher Suite {}", conn.getCipherSuite());
				logger.info("HTTP Headerfield {}", conn.getHeaderField(3));

				
				Certificate[] serverCertificate = conn.getServerCertificates();
				
				for (Certificate certificate : serverCertificate) {
					logger.info("SSL Certificate Type {}", certificate.getType());
					
					if (certificate instanceof X509Certificate) {
				        X509Certificate x509cert = (X509Certificate) certificate;

				        // Get subject
				        Principal principal = x509cert.getSubjectDN();
				        logger.info("SSL Certificate Subject DN {}", principal.getName());

				        // Get issuer
				        principal = x509cert.getIssuerDN();
				        logger.info("SSL Certificate IssuerDn {}", principal.getName());
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
	 * Gets factory for TLS
	 * @return
	 * @throws Exception
	 */
	private static SSLSocketFactory getFactorySimple() throws Exception {
		SSLContext context = SSLContext.getInstance("TLS");
		context.init(null, null, null);
		return context.getSocketFactory();
	}
}
