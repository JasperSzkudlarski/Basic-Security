package basicSercurityProject;


import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

public class DES 
{

    public static SecretKey GenDESKeys() throws NoSuchAlgorithmException, NoSuchPaddingException
    {
    	KeyGenerator keygenerator = KeyGenerator.getInstance("DES");
        SecretKey desKey = keygenerator.generateKey();
        
        return desKey;
    }
    
    public static Cipher generateDESCipher() throws NoSuchAlgorithmException, NoSuchPaddingException
    {
        Cipher desCipher; 
        desCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        
        return desCipher;
    }
    
    public static String Encrypt(String text, SecretKey desKey, Cipher desCipher) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
    {
        byte[] cipherBytes;
        byte[] bytes = Base64.getDecoder().decode(text);
        
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0 };
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        desCipher.init(Cipher.ENCRYPT_MODE, desKey, ivSpec);
        cipherBytes = desCipher.doFinal(bytes);
        System.out.println("message encrypted with DES");
        
        return Base64.getEncoder().encodeToString(cipherBytes);
    }
    
    public static String Decrypt(String cipherText, SecretKey desKey, Cipher desCipher) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
    {
        byte[] bytes;
        byte[] cipherBytes = Base64.getDecoder().decode(cipherText);
        
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0 };
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        desCipher.init(Cipher.DECRYPT_MODE, desKey, ivSpec);
        bytes = desCipher.doFinal(cipherBytes);
        System.out.println("message decrypted with DES");
        
        return Base64.getEncoder().encodeToString(bytes);
    }
    
    public static String readDESKeyFromFile(String keyFileName) throws IOException {
    	  FileReader in = new FileReader(keyFileName);
		  BufferedReader oin = new BufferedReader(in);
		  try
		  {
		    String keyStr = new String(oin.readLine());
		    
		    return keyStr;
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

}
