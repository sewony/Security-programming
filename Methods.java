import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Methods {
	static byte[] KeyGeneration(String password, byte[]salt, int dkLen, int iteration)throws Exception {
	
	Security.addProvider(new BouncyCastleProvider());
	MessageDigest md= MessageDigest.getInstance("SHA1","BC");
	byte[] input= new byte[password.length()+salt.length];//password+salt 길이를 가지는 배열 생성
	
	System.arraycopy(Utils.toByteArray(password), 0, input, 0, password.length());//input배열에 password를 붙여넣는다
	System.arraycopy(salt, 0, input, password.length(), salt.length);//input 배열에 salt를 붙여넣는다.
	
	System.out.println("Input : "+Utils.toHexString(input));
	
	md.update(input);//PBKDF1의 과정대로 진행한다
	
	for(int i=0;i<iteration-1;i++) {
		byte T[]=md.digest();
		md.update(T);
	}
	byte output[]=md.digest();
	byte[] derivedKey=new byte[16];
	
	System.arraycopy(output, 0, derivedKey, 0, dkLen);//16byte의 크기로 derived key를 뽑아낸다
	
	System.out.println("derivedKey : "+Utils.toHexString(derivedKey));
	return derivedKey;
	}

	static void FileEnc(byte[] salt, byte[] DerivedKey, String Path, String o_Path)throws Exception{
		Security.addProvider(new BouncyCastleProvider());
	byte[]	ivBytes=new byte[] {
		0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
		0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
	
	SecretKeySpec key= new SecretKeySpec(DerivedKey, "AES");
	IvParameterSpec iv= new IvParameterSpec(ivBytes);
	
	Cipher cipher=null;
	cipher=Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
	cipher.init(Cipher.ENCRYPT_MODE, key, iv);//암호화 모드로 initialization 
	
	byte[] password_check=new byte[16];//password를 체크하기 위한 배열 생성
	byte[] password_check_out=new byte[24];

	System.arraycopy(DerivedKey, 0, password_check_out, 0, DerivedKey.length);//password_check_out에 derivedKey값 복사
	System.arraycopy(salt, 0, password_check_out, 16, salt.length);//password_check_out에 salt값 복사
	MessageDigest hash= MessageDigest.getInstance("SHA1", "BC");

	password_check_out=hash.digest(password_check_out);//hash 함수에 넣고 결과를 얻어낸다.
	System.arraycopy(password_check_out, 0, password_check, 0, 16);//결과 중 16byte만 password_check에 복사
	System.out.println("password_check: "+Utils.toHexString(password_check));

	FileInputStream Inputstream= new FileInputStream(Path);//Inputstream 객체생성
	FileOutputStream Outputstream= new FileOutputStream(o_Path);//Outputstream 객체생성

	Outputstream.write(salt);//salt를 Outputstream 객체에 넣는다
	Outputstream.write(password_check);//password_check값을 Outputstream 객체에 넣는다

	int BUF_SIZE=1024;//아래로는 파일암호화 코드
	byte[] buffer= new byte[BUF_SIZE];  

	int read=BUF_SIZE;
	
	while((read=Inputstream.read(buffer,0,BUF_SIZE))==BUF_SIZE) {
		Outputstream.write(cipher.update(buffer,0,read));
	}
	Outputstream.write(cipher.doFinal(buffer,0,read));

	Inputstream.close();
	Outputstream.close();
	}

	static void FileDec(byte[] salt2, byte[] DerivedKey2, String o_Path2, String dec_path) throws Exception {

		byte[]		ivBytes=new byte[] {
		0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
		0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
	
		byte[] 	password_check=new byte[16];
		byte[] 	password_check_out=new byte[24];
		byte[] 	password_checkd=new byte[16];
		byte[] 	password_check_outd=new byte[24];

	SecretKeySpec key = new SecretKeySpec(DerivedKey2, "AES");
	IvParameterSpec iv= new IvParameterSpec(ivBytes);
	
	Security.addProvider(new BouncyCastleProvider());
	
	System.arraycopy(DerivedKey2, 0, password_check_out, 0, DerivedKey2.length);//password_check_out에 derivedKey값 복사
	System.arraycopy(salt2, 0, password_check_out, 16, salt2.length);//password_check_out에 salt값 복사
	MessageDigest hash= MessageDigest.getInstance("SHA1", "BC");
	password_check_out=hash.digest(password_check_out);//hash 함수에 넣고 결과를 얻어낸다.
	System.arraycopy(password_check_out, 0, password_check, 0, 16);//결과중 16byte만 password_check에 복사
	System.out.println("password_check: "+Utils.toHexString(password_check));//파라미터로 받은 값으로 이 메소드에서 만든 password check값
	
	FileInputStream Inputstream= new FileInputStream(o_Path2);//Inputstream 객체 생성
	FileOutputStream Outputstream= new FileOutputStream(dec_path);//Outputstream 객체 생성

	

	password_check_outd=Inputstream.readNBytes(24);//Inputstream에서 앞의 24바이트를 읽어옴
	for(int i=8;i<24;i++) {
	password_checkd[i-8]=password_check_outd[i];	//Inputstream의 password_check 부분만 password_check에 저장
	}
	System.out.println("password_checkd: "+Utils.toHexString(password_checkd));//Inputstream 객체에서 추출한 password check값

	int sum=0;
	for(int i=0;i<16;i++) {
	if(password_check[i]==password_checkd[i]) {//각 바이트마다 같은지 확인하여 같다면 sum++
		sum++;
		}
	}
	if(sum==16) {//password_check와 password_checkd가 일치하면 복호화진행

		Cipher cipher=null;
		cipher=Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, key, iv);

		int BUF_SIZE=1024;
		byte[] buffer= new byte[BUF_SIZE];
		int read=BUF_SIZE;

		while((read=Inputstream.read(buffer,0,BUF_SIZE))==BUF_SIZE) {
			Outputstream.write(cipher.update(buffer,0,read));
		}
		Outputstream.write(cipher.doFinal(buffer,0,read));

		Inputstream.close();
		Outputstream.close();
	}
	}}