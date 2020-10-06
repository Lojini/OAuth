package com.example.oauth;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeRequestUrl;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.FileContent;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;

import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.drive.Drive;
import com.google.api.services.drive.DriveScopes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.PostConstruct;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.File;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Controller
public class MainController {
    private static final Logger logger = LoggerFactory.getLogger(MainController.class);
    private static HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
    private static JacksonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
    @Value("${google.oauth.callback.uri}")
    private String CALLBACK_URI;

    @Value("${google.secret.key.path}")
    private Resource gdSecretKeys;

    @Value("${google.credentials.folder.path}")
    private Resource credentialsFolder;

    @Value("${app.temp.path}")
    private String tempPath;

    private static final List<String> SCOPES = Collections.singletonList(DriveScopes.DRIVE);
    private static final String USER_IDENTIFIER_KEY = "APP_USER";

    private GoogleAuthorizationCodeFlow flow;

    @PostConstruct
    public void init() throws Exception {
        GoogleClientSecrets secrets = GoogleClientSecrets.load(JSON_FACTORY,
                new InputStreamReader(gdSecretKeys.getInputStream()));
        flow = new GoogleAuthorizationCodeFlow.Builder(HTTP_TRANSPORT, JSON_FACTORY, secrets, SCOPES)
                .setDataStoreFactory(new FileDataStoreFactory(credentialsFolder.getFile())).build();
    }

    @GetMapping(value = {"/"})
    public String showHomePage() throws Exception {
        boolean isUserAuthenticated = false;
        Credential credential = flow.loadCredential(USER_IDENTIFIER_KEY);
        if (credential != null) {
            boolean tokenValid = credential.refreshToken();
            if (tokenValid)
                isUserAuthenticated = true;

        }
        return isUserAuthenticated ? "upload.html" : "index.html";
    }

    @GetMapping(value = {"/google-oauth"})
    public void doGoogleSignIn(HttpServletResponse response) throws Exception {
        GoogleAuthorizationCodeRequestUrl url = flow.newAuthorizationUrl();
        String redirectURL = url.setRedirectUri(CALLBACK_URI).setAccessType("offline").build();
        response.sendRedirect(redirectURL);
    }

    @GetMapping(value = {"/oauth"})
    public String saveAuthorizationCode(HttpServletRequest request) throws Exception {
        String code = request.getParameter("code");
        if (code != null) {
            saveToken(code);
            return "upload.html";
        }
        return "index.html";
    }

    private void saveToken(String code) throws Exception {
        GoogleTokenResponse response = flow.newTokenRequest(code).setRedirectUri(CALLBACK_URI).execute();
        flow.createAndStoreCredential(response, USER_IDENTIFIER_KEY);
    }

    @PostMapping(value = {"/upload"})
    public void uploadFile(@RequestParam("file") MultipartFile file) throws Exception {
        Credential cred = flow.loadCredential(USER_IDENTIFIER_KEY);
        Drive drive = new Drive.Builder(HTTP_TRANSPORT, JSON_FACTORY, cred).setApplicationName("SpringBootOAuth").build();

        String fileName = file.getOriginalFilename();
        String fileType= file.getContentType();

        File copyFile = new File(tempPath,fileName);
        file.transferTo(copyFile);

        FileContent fileContent = new FileContent(fileType, copyFile);
        com.google.api.services.drive.model.File metaFile = new com.google.api.services.drive.model.File();
        metaFile.setName(fileName);

        com.google.api.services.drive.model.File verifyFile = drive.files().create(metaFile, fileContent)
                .setFields("id").execute();
        logger.info("Created File: " + verifyFile.getId());
    }

    @PostMapping(value = {"/uploadFiles"})
    public void uploadFiles(@RequestParam("files") MultipartFile[] files) throws Exception {
        for (MultipartFile multipartFile : Arrays.asList(files)) {
            uploadFile(multipartFile);
        }
    }
    @GetMapping(value = {"/logout"})
    public String logout(HttpServletRequest request){
        HttpSession session = request.getSession(false);
        session = request.getSession(true);
        if (session != null) {
            session.invalidate();
            logger.info("Logged Out...");
            return "index.html";
        }
        return null;
    }


}
