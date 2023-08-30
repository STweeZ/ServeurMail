package fr.univartois.m1.securitemail;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

public class X509 {

	public static X509Certificate lectureX509(String file)
			throws IOException, CertificateException, NullPointerException {
		InputStream x509 = new FileInputStream(file);
		PEMParser parser = new PEMParser(new InputStreamReader(x509));
		X509CertificateHolder certHolder = (X509CertificateHolder) parser.readObject(); // Lecture du X509
		x509.close();
		return new JcaX509CertificateConverter().setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())
				.getCertificate(certHolder);
	}

}
