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




	}




}
