package fr.univartois.m1.securitemail;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Enumeration;

import org.javatuples.Pair;

public class P12 {

	public static Pair<Certificate, PrivateKey> lectureP12(String file, String password)
			throws IOException, KeyStoreException, Exception {
		InputStream p12 = new FileInputStream(file);
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(p12, password.toCharArray());

		Enumeration<String> aliasEnum = ks.aliases();
		Key key = null;
		Certificate cert = null;

		String keyName;
		while (aliasEnum.hasMoreElements()) {
			keyName = (String) aliasEnum.nextElement();
			if (ks.isKeyEntry(keyName)) { // Récupération de la clé privée et du certificat
				key = ks.getKey(keyName, password.toCharArray());
				cert = ks.getCertificate(keyName);
				break;
			}
		}
		p12.close();
		return new Pair<Certificate, PrivateKey>(cert, (PrivateKey) key);
	}

}
