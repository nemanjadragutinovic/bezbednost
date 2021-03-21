package Busep.controller;

import Busep.ModelDTO.SubjectDTO;
import Busep.Services.OCSPService;
import Busep.Services.SubjectService;
import Busep.model.Subject;
import keyStore.KeyStoreReader;
import keyStore.KeyStoreWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@RestController
@RequestMapping(value = "/subject")
public class SubjectController {

    @Autowired
    SubjectService subjectService;

    @PostMapping
    public void newSubject(@RequestBody SubjectDTO subjectDTO){
        subjectService.newSubject(subjectDTO);
    }

    @GetMapping(value = "/zahteviSubjekata")
    public ResponseEntity<List<SubjectDTO>> getAllSubjects() {
        List<Subject> subjects = subjectService.findAll();
        List<SubjectDTO> subjectDTOList = new ArrayList<>();
        for(Subject subject : subjects) {
            if(subject.isCert() == false) {
                subjectDTOList.add(new SubjectDTO(subject));
            }
        }

        return new ResponseEntity<>(subjectDTOList, HttpStatus.OK);
    }




    }


}
