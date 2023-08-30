package fr.univartois.m1.securitemail;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Properties;

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.mail.BodyPart;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.SendFailedException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.ByteArrayDataSource;

import org.javatuples.Pair;

public class SMTP {

	public static void sendMail(Properties props, String to)
			throws MessagingException, IOException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		Properties properties = new Properties();
		try {
			properties.put("mail.smtp.host", props.get("smtp.ip"));
			properties.put("mail.smtp.port", 25);
		} catch (NullPointerException e) {
			System.out.println("\n\tInformations manquantes dans le fichier 'local.properties'.\n");
			return;
		}

		Session session = Session.getDefaultInstance(properties);

		MimeMessage message = new MimeMessage(session);
		message.setFrom(new InternetAddress((String) props.get("smtp.user")));
		message.addRecipient(Message.RecipientType.TO, new InternetAddress(to));

		System.out.print("Mot de passe du p12 : ");
		String p12pwd = Main.reader.readLine();

		Pair<Certificate, PrivateKey> sbireP12 = null;
		try {
			sbireP12 = P12.lectureP12((String) props.get("sbire.p12"), p12pwd);
		} catch (KeyStoreException e) {
			System.out.println("\n\tErreur lors de la récupération des clés du P12.\n");
			return;
		} catch (Exception e) {
			System.out.println("\n\tErreur lors de l'ouverture du P12.\n");
			return;
		}

		String textIn = null;
		String textInCrypted = null;
		try {
			System.out.print("Sujet : ");
			message.setSubject(Cryptage.crypterMessage(sbireP12.getValue1(), Main.reader.readLine()));

			System.out.print("Message : ");
			textIn = Main.reader.readLine();
			textInCrypted = Cryptage.crypterMessage(sbireP12.getValue1(), textIn);

			BodyPart p12Part = new MimeBodyPart();
			DataSource p12Src = new ByteArrayDataSource(Base64.getEncoder().encode(sbireP12.getValue0().getEncoded()),
					"application/p12");
			p12Part.setDataHandler(new DataHandler(p12Src));
			p12Part.setHeader("Content-Transfer-Encoding", "quoted-printable");

			BodyPart textPart = new MimeBodyPart();
			DataSource textSrc = new ByteArrayDataSource(textInCrypted, "application/secret");
			textPart.setDataHandler(new DataHandler(textSrc));
			textPart.setHeader("Content-Transfer-Encoding", "quoted-printable");

			BodyPart signPart = new MimeBodyPart();
			DataSource signSrc = new ByteArrayDataSource(Cryptage.crypterMessage(sbireP12.getValue1(),
					Base64.getEncoder().encodeToString(Hachage.hash(textIn))), "application/signature");
			signPart.setDataHandler(new DataHandler(signSrc));
			signPart.setHeader("Content-Transfer-Encoding", "quoted-printable");

			MimeMultipart multi = new MimeMultipart("alternative");

			multi.addBodyPart(p12Part);
			multi.addBodyPart(textPart);
			multi.addBodyPart(signPart);

			message.setContent(multi);
		} catch (NullPointerException e) {
			System.out.println("\n\n\tImpossible d'accéder aux informations du P12.\n");
			return;
		} catch (Exception e) {
			System.out.println("\n\tErreur de traitement des informations à la construction du mail.\n");
			return;
		}

		try {
			Transport.send(message);
			System.out.println("\n\tMessage envoyé.\n");
		} catch (SendFailedException e) {
			System.out.println("\n\tErreur lors de l'envoi : adresse mail invalide.\n");
			return;
		} catch (Exception e) {
			System.out.println(
					"\n\tErreur lors de l'envoi : vérifier les informations fournies dans le fichier 'local.properties'.\n");
			return;
		}
	}

}
