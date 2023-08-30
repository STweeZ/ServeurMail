package fr.univartois.m1.securitemail;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;

import javax.activation.DataHandler;
import javax.mail.BodyPart;
import javax.mail.Folder;
import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Store;
import javax.mail.internet.MimeMultipart;

public class POP3 {

	public static void getMail(Properties props) throws Exception {
		Properties properties = System.getProperties();
		properties.put("mail.pop3.host", props.get("pop3.ip"));
		properties.put("mail.pop3.port", 110);
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

		Session session = Session.getDefaultInstance(properties);

		Store store = session.getStore("pop3");
		store.connect((String) props.get("pop3.ip"), (String) props.get("pop3.user"),
				(String) props.get("pop3.password"));
		Folder inbox = null;
		Message[] messages = null;

		try {
			inbox = store.getFolder("INBOX");
			inbox.open(Folder.READ_ONLY);
			System.out.println();
			messages = inbox.getMessages();
		} catch (Exception e) {
			System.out.println("\n\tImpossible d'accéder à la boîte mail.\n");
			return;
		}

		if (messages.length == 0)
			System.out.println("\tPas de messages pour l'instant.\n");
		for (int i = 0; i < messages.length; i++) {
			System.out.println((i + 1) + ".");
			MimeMultipart multiPart = (MimeMultipart) messages[i].getContent();

			PublicKey clePublique = null;
			Certificate p12 = null;
			String signature = null;
			String message = null;
			String sujet = null;

			try {
				for (int j = 0; j < multiPart.getCount(); j++) {
					BodyPart bodyPart = multiPart.getBodyPart(j);
					DataHandler data = bodyPart.getDataHandler();

					BufferedInputStream bis = new BufferedInputStream((InputStream) data.getContent());
					ByteArrayOutputStream baos = new ByteArrayOutputStream();
					while (true) {
						int c = bis.read();
						if (c == -1)
							break;
						baos.write(c);
					}
					String input = new String(baos.toByteArray());

					if (data.getContentType().equals("application/p12")) {
						p12 = certFactory
								.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(input))); // Reconstruction du certificat reçu
						clePublique = p12.getPublicKey();
					} else if (data.getContentType().equals("application/secret"))
						message = Cryptage.decrypterMessage(clePublique, input);
					else if (data.getContentType().equals("application/signature"))
						signature = Cryptage.decrypterMessage(clePublique, input);
				}
			} catch (Exception e) {
				System.out.println("\tErreur lors de la récupération des informations du mail.\n");
				prettierTerminal(i, messages.length);
				continue;
			}

			try {
				sujet = Cryptage.decrypterMessage(clePublique, messages[i].getSubject());
			} catch (Exception e) {
				System.out.println("\tErreur lors du décryptage du sujet du mail.\n");
				prettierTerminal(i, messages.length);
				continue;
			}

			byte[] hashMessage = null;
			try {
				hashMessage = Hachage.hash(message);
			} catch (Exception e) {
				System.out.println("\tErreur lors du hachage du contenu du mail.\n");
				prettierTerminal(i, messages.length);
				continue;
			}

			if (!Arrays.equals(Base64.getDecoder().decode(signature), hashMessage)) {
				System.out.println("\tClé publique de l'émetteur non valide.");
				continue;
			}

			X509Certificate x509 = null;
			try {
				x509 = X509.lectureX509((String) props.get("boss.x509"));
			} catch(Exception e) {
				System.out.println("\tErreur d'accès au X.509 du boss.\n");
				prettierTerminal(i, messages.length);
				continue;
			}
			
			
			try {
				p12.verify(x509.getPublicKey());
			} catch (SignatureException e) {
				System.out.println("\tMail non authentifié par le boss.\n");
				prettierTerminal(i, messages.length);
				continue;
			} catch (Exception e) {
				System.out.println("\tÉchec de vérification du mail.\n");
				prettierTerminal(i, messages.length);
				continue;
			}

			try {
				System.out.println(messages[i].getSentDate());
				System.out.println("De: " + messages[i].getFrom()[0]);
				System.out.println("Sujet: " + sujet);
				System.out.println(message + "\n");
			} catch (Exception e) {
				System.out.println("\tErreur d'accès aux informations du mail.\n");
				prettierTerminal(i, messages.length);
				continue;
			}
			prettierTerminal(i, messages.length);
		}
		inbox.close(false);
		store.close();
	}

	private static void prettierTerminal(int i, int len) {
		if (i < (len - 1))
			System.out.print("\n");
	}

}