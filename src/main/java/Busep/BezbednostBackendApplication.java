package Busep;

import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;

@SpringBootApplication
public class BezbednostBackendApplication {

	public static void main(String[] args) throws CertificateException, IOException, OperatorCreationException, KeyStoreException {
		SpringApplication.run(BezbednostBackendApplication.class, args);

		//Inicializacija pocetnog root sertifikata jer mora postojati pocetni zbog dana vazenja, da ne puca fajl i da se postave
		//pocetni fajlovi

		/*KeyStoreWriter ks=new KeyStoreWriter();
		char[] array = "tim3".toCharArray();

		//ks.loadKeyStore("endCertificate.jks",array);

		ks.loadKeyStore(null,array);
		//ks.saveKeyStore("endCertificate.jks", array);
		KeyPair rootCertKeyPar = ks.generateKeyPair();

		CertificateGenerator certificate = new CertificateGenerator();
		X509Certificate cert = certificate.generate(rootCertKeyPar, "SHA256WithRSAEncryption", "RootCert", 7300);

		ks.write("root", rootCertKeyPar.getPrivate(), array, cert);

		ks.saveKeyStore("rootCertificate.jks", array);


		KeyStoreReader kr=new KeyStoreReader();
		kr.readCertificate("rootCertificate.jks", "tim3", "root");
		System.out.println(cert);*/


////////////////////////////////////

		//pravljenje inter fajla

		/*KeyStoreWriter ks=new KeyStoreWriter();
		char[] array = "tim3".toCharArray();
		ks.loadKeyStore(null,array);


		ks.saveKeyStore("interCertificate.jks", array);*/

	}




}
