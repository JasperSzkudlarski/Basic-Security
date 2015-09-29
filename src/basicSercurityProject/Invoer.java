package basicSercurityProject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

/**
 * Deze klasse verzorgt eenvoudige invoer vanaf het toetsenbord.
 */
public class Invoer {
	
	private static BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
	
	/**
	 * Deze methode drukt de boodschap message op het scherm en leest daarna een integer 
	 * getal van de invoer.
	 * Wanneer meerdere integer getallen na elkaar gevraagd worden, wordt de boodschap slechts 
	 * eenmaal getoond indien de invoer op 1 lijn staat.
	 * Bij foutieve invoer wordt een bericht op de uitvoer geschreven en als resultaat 0 
	 * teruggegeven.
	 * 
	 *
	 * @param	message	Het te tonen bericht
	 */
	public static int leesInt(String message) {
		if (tokens==null||!tokens.hasMoreTokens())
		System.out.println(message);
		return leesInt();
	}
	
	/**
	 * Deze methode leest een integer getal van de invoer.
	 * Bij foutieve invoer wordt een bericht op de uitvoer geschreven en als resultaat 0 
	 * teruggegeven.
	 */
	public static int leesInt() {
		try {
			String temp = nextToken();
			return Integer.parseInt(temp);
		} catch (IOException ioe) {
			System.out.println("Fout tijdens het lezen van een integer");
			return 0;
		} catch (NumberFormatException nfe) {
			System.out.println("Fout tijdens het lezen van een integer");
			return 0;
		}
	}
	
	/**
	 * Deze methode drukt de boodschap message op het scherm en leest daarna een double 
	 * getal van de invoer.
	 * Bij foutieve invoer wordt een bericht op de uitvoer geschreven en als resultaat 0 
	 * teruggegeven.
	 *
	 * @param	message	Het te tonen bericht
	 */
	public static double leesDouble(String message) {
		System.out.println(message);
		return leesDouble();
	}
	
	/**
	 * Deze methode leest een double getal van de invoer.
	 * Bij foutieve invoer wordt een bericht op de uitvoer geschreven en als resultaat 0 
	 * teruggegeven.
	 */
	public static double leesDouble() {
		try {
			String temp = nextToken();
			return Double.parseDouble(temp);
		} catch (IOException ioe) {
			System.out.println("Fout tijdens het lezen van een double");
			return 0;
		} catch (NumberFormatException nfe) {
			System.out.println("Fout tijdens het lezen van een double");
			return 0;
		}
	}

	/**
	 * Deze methode drukt de boodschap message op het scherm en leest daarna een float getal 
	 * van de invoer.
	 * Bij foutieve invoer wordt een bericht op de uitvoer geschreven en als resultaat 0 
	 * teruggegeven.
	 *
	 * @param	message	Het te tonen bericht
	 */
	public static float leesFloat(String message) {
		System.out.println(message);
		return leesFloat();
	}
	
	/**
	 * Deze methode leest een float getal van de invoer.
	 * Bij foutieve invoer wordt een bericht op de uitvoer geschreven en als resultaat 0 
	 * teruggegeven.
	 */
	public static float leesFloat() {
		try {
			String temp = nextToken();
			return Float.parseFloat(temp);
		} catch (IOException ioe) {
			System.out.println("Fout tijdens het lezen van een float");
			return 0;
		} catch (NumberFormatException nfe) {
			System.out.println("Fout tijdens het lezen van een float");
			return 0;
		}
	}

	/**
	 * Deze methode drukt de boodschap message op het scherm en leest daarna een karakter 
	 * van de invoer.
	 * Bij foutieve invoer wordt een bericht op de uitvoer geschreven en als resultaat ' ' 
	 * (spatie) teruggegeven.
	 *
	 * @param	message	Het te tonen bericht
	 */
	public static char leesChar(String message) {
		System.out.println(message);
		return leesChar();
	}

	/**
	 * Deze methode leest een karakter van de invoer.
	 * Bij foutieve invoer wordt een bericht op de uitvoer geschreven en als resultaat ' ' 
	 * (spatie) teruggegeven.
	 */
	public static char leesChar() {
		try {
			String temp = in.readLine();
			return temp.charAt(0);
		} catch (IOException ioe) {
			System.out.println("Fout tijdens het lezen van een karakter");
			return ' ';
		}
	}

	/**
	 * Deze methode drukt de boodschap message op het scherm en leest daarna een string 
	 * van de invoer.
	 *
	 * @param	message	Het te tonen bericht
	 */
	public static String leesString(String message) {
		System.out.println(message);
		return leesString();
	}
	
	/**
	 * Deze methode leest een string van de invoer
	 */
	public static String leesString() {
		try {
			return in.readLine();
		} catch (IOException ioe) {
			System.out.println("Fout tijdens het lezen van een string");
			return "";
		}
	}
	
	private static java.util.StringTokenizer tokens;
	private static String nextToken() throws IOException {
		while (tokens==null||!tokens.hasMoreElements()) {
			tokens=new java.util.StringTokenizer(in.readLine());
		}
		return tokens.nextToken();
	}

}
