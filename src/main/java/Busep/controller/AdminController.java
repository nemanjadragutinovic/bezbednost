package Busep.controller;


import Busep.ModelDTO.AdminDTO;
import Busep.ModelDTO.SubjectDTO;
import Busep.Repository.SubjectRepository;
import Busep.Services.AdminServices;
import Busep.Services.SubjectService;
import Busep.certificates.CertificateGenerator;
import Busep.model.Admin;
import Busep.model.Subject;
import keyStore.KeyStoreReader;
import keyStore.KeyStoreWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@RestController

@RequestMapping(value = "/admin")
public class AdminController {

    @Autowired
    AdminServices adminServices;

    @Autowired
    SubjectService subjectService;

    @Autowired
    SubjectRepository subjectRepository;

    @GetMapping(value = "/sviAdmini")
    public ResponseEntity<List<AdminDTO>> getPostojeceAdmine() {


        List<Admin> admini = adminServices.findAll();

        List<AdminDTO> adminDTOList = new ArrayList<>();
        for (Admin admin : admini) {

            adminDTOList.add(new AdminDTO(admin));

        }

        return new ResponseEntity<>(adminDTOList, HttpStatus.OK);
    }


    @PostMapping(value="/addCertificate/{check}/{dani}/{zahtevId}", consumes = MediaType.APPLICATION_JSON_VALUE)
    public void createCertificate(@PathVariable String check, @PathVariable String dani, @PathVariable String zahtevId) throws CertificateException, OperatorCreationException, IOException, ParseException, NoSuchFieldException, IllegalAccessException {

        long num = Long.parseLong(zahtevId);
        int danii = Integer.parseInt(dani);
        Subject subject = subjectService.findOne((num));
        subject.setCert(true);





        if(check.equals("true")){

            subject.setCA(true);
        }
        subjectRepository.save(subject);
        KeyStoreWriter ks=new KeyStoreWriter();
        KeyPair keyPar = ks.generateKeyPair();
        SubjectDTO subjectDTO= new SubjectDTO(subject);
        char[] array = "tim3".toCharArray();
        CertificateGenerator certgen= new CertificateGenerator();
        Certificate certIn =certgen.generateRootOrEnd(subjectDTO, keyPar, "SHA256WithRSAEncryption",danii);
        KeyStoreReader kr=new KeyStoreReader();
        if(check.equals("true")){
            ks.loadKeyStore("interCertificate.jks",array);
            ks.write(subject.getId().toString(), keyPar.getPrivate() ,  subject.getId().toString().toCharArray(), certIn);
            ks.saveKeyStore("interCertificate.jks", array);
            X509Certificate cert = (X509Certificate) kr.readCertificate("interCertificate.jks", "tim3", zahtevId);
            System.out.println(cert);
        }else{
            ks.loadKeyStore("endCertificate.jks",array);
            ks.write(subject.getId().toString(), keyPar.getPrivate() ,  subject.getId().toString().toCharArray(), certIn);
            ks.saveKeyStore("endCertificate.jks", array);
            X509Certificate cert = (X509Certificate) kr.readCertificate("endCertificate.jks", "tim3", zahtevId);
            System.out.println(cert);
        }

    };



    @GetMapping(value = "/getDani/{check}")
    public ArrayList<?> dozvoljeniDani(@PathVariable String check){
        ArrayList<Integer> dozvoljeni= new ArrayList<Integer>();
        char[] array = "tim3".toCharArray();
        System.out.println("ovo je check" + check);
        KeyStoreWriter ks=new KeyStoreWriter();
        ks.loadKeyStore("rootCertificate.jks",array);
        KeyStoreReader kr=new KeyStoreReader();

        X509Certificate certRoot = (X509Certificate) kr.readCertificate("rootCertificate.jks", "tim3", "root");
        Instant now = Instant.now();
        Date pocetniDan = Date.from(now);
        System.out.println(pocetniDan + "pocetni dan");
        Date dan = certRoot.getNotAfter();
        System.out.println(dan + "krajnji dan");
        LocalDate localDate = dan.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        System.out.println(localDate + "krajnji dan konvertovan");
        LocalDate pocetni = pocetniDan.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        System.out.println(pocetni + "pocetni dan konvertovan");
        //Period period =  Period.between(pocetni, localDate);
        //System.out.println(period + "period izmedju pocetnog i krajnjeg dana");
        long daysBetween = ChronoUnit.DAYS.between(pocetni, localDate);
        //int diff = period.getDays();
        System.out.println(daysBetween + "ukupno dana izmedju pocetnog i krjanjeg datuma");

        int godine=(int)daysBetween/365;
        int maxYear = 0;
        if(check.equals("true")) {

            maxYear = 15;
        } else {
            maxYear = 10;
        }
        for(int i=1; i<=godine; i++){

            dozvoljeni.add(365*i);
            System.out.println(365*i);
            if( i == maxYear) {
                break;
            }
        }

        return dozvoljeni;
    };





}
