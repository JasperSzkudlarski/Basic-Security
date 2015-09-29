package basicSercurityProject;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Hash 
{
	public static String HashIt(String text) throws NoSuchAlgorithmException
	{
		byte[] textBytes;
		byte[] cipherTextBytes;
		String cipherStr;
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		
		textBytes = text.getBytes();
		cipherTextBytes = md.digest(textBytes);
		cipherStr = Base64.getEncoder().encodeToString(cipherTextBytes);
		System.out.println("message hashed");
		
		return cipherStr;
	}
}
