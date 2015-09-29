package basicSercurityProject;

import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.*;

public class Main {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException 
	{
		String message;
		Cipher rsaCipher;
		Cipher desCipher;
		SecretKey desKey;
		String encryptedDESKey;
		
		rsaCipher = RSA.GenerateRSACipher();
		desCipher = DES.generateDESCipher();
		
		if(!(new File("private_A.key").isFile()) || !(new File("public_A.key").isFile()) || !(new File("private_B.key").isFile()) || !(new File("public_B.key").isFile())) 
		{  
			RSA.GenerateRSAKeys();
		}
		
		if(new File("File_2").isFile())
		{
			encryptedDESKey = DES.readDESKeyFromFile("File_2");
			desKey = RSA.RSADecryptKey(encryptedDESKey, rsaCipher);
		}
		else
		{
			desKey = DES.GenDESKeys();
		}
		
		System.out.println("Alice: ");
		message = Invoer.leesString("enter message: ");
		
		while((!(message.equals(""))) && (!(message.toLowerCase().trim().equals("terminate"))))
		{
		SendMessage(message, rsaCipher,desCipher, desKey);
		RecieveMessage(rsaCipher, desCipher);
		System.out.println("to terminate, don't enter a message or type \"terminate\" as the message: ");
		message = Invoer.leesString("next message: ");
		}
		
		
	}
	
	public static void saveStringToFile(String fileName, String text) throws IOException 
	{
			File f = new File(fileName);
			FileWriter f2 = new FileWriter(fileName, false);
			  try 
			  {
			    if(new File(fileName).isFile())
			    {
			    	f.delete();
			    }
			    
			    f2.write(text);
			  } 
			  catch (Exception e) 
			  {
			    throw new IOException("Unexpected error", e);
			  } 
			  finally 
			  {
			    f2.close();
			  }
	}
	
	private static String readStringFromFile(String fileName) throws IOException
	{
		  FileReader in = new FileReader(fileName);
		  BufferedReader oin = new BufferedReader(in);
		  try
		  {
		    String message = (String)oin.readLine();
		    
		    return message;
		  } 
		  catch (Exception e) 
		  {
		    throw new RuntimeException(e);
		  } 
		  finally
		  {
		    oin.close();
		  }
	}
	
	private static void SendMessage(String message, Cipher rsaCipher, Cipher desCipher, SecretKey desKey) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException
	{
		String messageHashAlice;
		String encryptedMessage;
		String encryptedDESKey;
		
		message = message.trim();
		
		messageHashAlice = Hash.HashIt(message);
		messageHashAlice = RSA.RSASignString(messageHashAlice, rsaCipher);
		saveStringToFile("File_3", messageHashAlice);
		
		while(message.length() % 4 != 0)
		{
			message += "/";
		}
		
		encryptedMessage = DES.Encrypt(message, desKey, desCipher);
		saveStringToFile("File_1", encryptedMessage);
		
		encryptedDESKey = RSA.RSAEncryptKey(desKey, rsaCipher);
		saveStringToFile("File_2", encryptedDESKey);
	}
	
	private static void RecieveMessage(Cipher rsaCipher, Cipher desCipher) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
	{
		String encryptedMessage;
		String encryptedDESKey;
		SecretKey desKey;
		String message;
		String messageHashBob;
		String recievedHash;
		
		System.out.println("Bob:");
		encryptedDESKey = readStringFromFile("File_2");
		desKey = RSA.RSADecryptKey(encryptedDESKey, rsaCipher);
		
		encryptedMessage = readStringFromFile("File_1");
		message = DES.Decrypt(encryptedMessage, desKey, desCipher);
		
		while(message.substring(message.length()-1).equals("/"))
		{
			message = message.substring(0, message.length()-1);
		}
		
		System.out.println("boodschap van Alice: " + message);
		messageHashBob = Hash.HashIt(message);
		recievedHash = RSA.RSAUnsignString( readStringFromFile("File_3"), rsaCipher);
		
		if(!(messageHashBob.equals(recievedHash)))
		{
			System.out.println("Hashes are not the same!");
		}
		System.out.println("hashes compaired");
	}

}
