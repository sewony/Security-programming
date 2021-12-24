import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.security.Security;
import java.io.FileNotFoundException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
//import java.security.Provider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main extends Methods {

	public static void main(String[] args) throws Exception, FileNotFoundException{
		// TODO Auto-generated method stub
		byte[] Salt= {0x78,0x57,(byte)0x8E, 0x5A, 0x5D, 0x63, (byte)0xCB, 0x06};
	    InputStream in = System.in;
	    InputStreamReader reader= new InputStreamReader(in);
	    BufferedReader br = new BufferedReader(reader);
	    
	    String Mode="";
	    String Password="";			
		String Filepath="";
		String o_path = ""; 
		String decpath =""; 
		
		System.out.print("Mode: ");
		Mode=br.readLine();
		System.out.print("password: ");
		Password=br.readLine();
		System.out.print("path: ");
		Filepath=br.readLine();
		System.out.print("o_path: ");
		o_path=br.readLine();
		System.out.print("decpath: ");
		decpath=br.readLine();
		
		byte[]derivedKey=KeyGeneration(Password, Salt, 16, 1000);//입력한 password를 기반으로 key 생성
		if(Mode.equals("Enc")) {//Enc 입력시 파일암호화 시작
			FileEnc(Salt, derivedKey, Filepath, o_path);
		}
		else if(Mode.equals("Dec")) {//Dec 입력시 password를 체크하고 맞다면 복호화 시작
			FileDec(Salt, derivedKey, o_path, decpath);
			}
		}
	
}
