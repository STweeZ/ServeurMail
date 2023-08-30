package fr.univartois.m1.securitemail;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Properties;

public class Main {
	private static final String ENVOI = "1";
	private static final String RECEPTION = "2";
	private static final String QUIT = "3";
	public static Properties props;
	public static final BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

	public static void main(String[] args) throws Exception {
		props = new Properties();
		InputStream in = new FileInputStream("./local.properties");
		try {
			props.load(in);
			in.close();
		} catch (NullPointerException e) {
			System.out.println("Pas de fichier local.properties");
			return;
		}

		while (true) {
			System.out.print(
					"Que souhaitez-vous faire ?\n1 pour envoyer un mail.\n2 pour consulter votre boîte mail.\n3 pour quitter.\n>");
			String name = reader.readLine();
			while (!name.equals(ENVOI) && !name.equals(RECEPTION) && !name.equals(QUIT)) {
				name = reader.readLine();
			}
			if (name.equals(ENVOI)) {
				System.out.print("\nAdresse de destination : ");
				String to = reader.readLine();
				SMTP.sendMail(props, to);
				System.out.println("<--------------------------------->\n");
			} else if (name.equals(RECEPTION)) {
				POP3.getMail(props);
				System.out.println("<--------------------------------->\n");
			} else {
				System.out.println("\nMerci d'avoir utilisé ce programme.\nAu revoir.\n\nGrégoire Delacroix\n");
				return;
			}
		}
	}

}