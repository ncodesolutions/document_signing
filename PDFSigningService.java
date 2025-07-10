/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ncode.invoice.pki.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

/**
 *

 */
public class PDFSigningServices extends FileSigningServices {

    private static final Logger logger = LogManager.getLogger(PDFSigningServices.class);

    private static final String PKCS11_KEYSTORE_TYPE = "PKCS11";

    public static int signPDF(PrivateKey key, Certificate[] chain, String providerName, String inFile, String outFile, boolean debug, int llx, int lly, int urx, int ury, String pageNo, String url, String reason, String loctaion) {
        {
            try {

                if (!isFileExists(inFile)) {

                    errorCode = ERROR_SOURCE_FILE_NOT_FOUND;

                    return ERROR_SOURCE_FILE_NOT_FOUND;

                }

                PdfReader reader = new PdfReader(inFile);

                FileOutputStream fout = new FileOutputStream(outFile);

                int totPages = 0;

                int[] showSigOnPages = null;

                totPages = reader.getNumberOfPages();

                showSigOnPages = getPagesToShowSign(totPages, pageNo);
                System.out.println("signPDF" + key);

                signPDFMultiplePage(reader, fout, true, key, chain, new Rectangle(llx, lly, urx, ury), showSigOnPages, url, reason, loctaion, providerName);

                System.out.println("signing completed");

                errorCode = SUCCESSFULL;

                return SUCCESSFULL;

            } catch (SecurityException ex) {

                logger.info("ERROR", ex);

                errorCode = ERROR_WRITE_PERMISSION_DEST_FILE;

                return errorCode;

            } catch (IOException ex) {

                logger.info("ERROR", ex);

                errorCode = ERROR_WRITING_DEST_FILE;

                return errorCode;

            } catch (Exception ex) {

                logger.info("ERROR", ex);

                ex.printStackTrace(System.out);

                errorCode = ERROR_UNKNOWN;

                return errorCode;
            }

        }

    }

    public static void signPDFMultiplePage(PdfReader reader, OutputStream output, boolean showSignature, PrivateKey key, Certificate[] chain, Rectangle box, int[] pageToShowSign, String imagePath, String reason, String loctaion, String providerName) throws Exception {

        System.out.println("Singing please wait...");

        OutputStream tmpOut = null;

        String tmpFilePath = null;

        File tmpFileObj = null;

        InputStream tmpInStream = null;

        for (int cnt = 0; cnt < pageToShowSign.length; cnt++) {

            if (cnt < pageToShowSign.length - 1) //
            {

                tmpFileObj = PrivilagedFunctions.createTempFile("tmpSig.pdf");

                tmpFileObj.deleteOnExit();

                tmpFilePath = tmpFileObj.getAbsolutePath();

                tmpOut = PrivilagedFunctions.getFileOutputStream(tmpFilePath);

            } else //set actual out put stream when last page comes.
            {

                tmpFilePath = null;

                tmpOut = output;
            }
            System.out.println("signPDFMultiplePage" + key);
            signAndEncryptPDF(reader, tmpOut, showSignature, key, chain, box, pageToShowSign[cnt], null, null, reason, loctaion, providerName);

            if (tmpFilePath != null) {

                tmpInStream = PrivilagedFunctions.getFileInputStream(tmpFilePath);

                reader = new PdfReader(tmpInStream);

                tmpInStream.close();
            }

        }

        if (tmpFilePath != null) {

            tmpInStream.close();

        }
    }

    public static void signAndEncryptPDF(PdfReader reader, OutputStream output, boolean showSignature, PrivateKey key, Certificate[] chain, Rectangle box, int pageToShowSign, String outPass, String signImage, String reason, String location, String providerName) throws Exception {

        System.out.println("signAndEncryptPDF" + key);
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }

        PdfStamper stamper = PdfStamper.createSignature(reader, output, '\0', null, true);
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();

        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setAcro6Layers(false);
        appearance.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);

        appearance.setVisibleSignature(box, pageToShowSign, System.currentTimeMillis() + "");

        ExternalDigest digest = new BouncyCastleDigest();
//        ExternalSignature signature = new PrivateKeySignature(key, DigestAlgorithms.SHA256, PKCS11_KEYSTORE_TYPE);
        ExternalSignature signature = new PrivateKeySignature(key, "SHA256", providerName);

        MakeSignature.signDetached(appearance, digest, signature, chain, null, null, null, 0, MakeSignature.CryptoStandard.CMS);
    }

    private static int[] getPagesToShowSign(int totPages, String pagesToShowSign) {

        int[] pages = null;

        String[] strPages = null;

        if (pagesToShowSign == null || pagesToShowSign.trim().length() == 0) {

            pages = new int[1];

            pages[0] = 1; //set to first page

        } else if (pagesToShowSign.trim().equalsIgnoreCase("A")) {

            pages = new int[totPages]; // all pages

            for (int i = 0; i < totPages; i++) {

                pages[i] = i + 1;

            }

        } else if (pagesToShowSign.trim().equalsIgnoreCase("L")) {

            pages = new int[1]; // Set Last pages

            pages[0] = totPages;

        } else if (pagesToShowSign.trim().equalsIgnoreCase("F")) {

            pages = new int[1]; // Set First pages

            pages[0] = 1;

        } else {

            strPages = pagesToShowSign.trim().split(",");

            pages = new int[strPages.length];

            for (int i = 0; i < strPages.length; i++) {

                try {

                    pages[i] = Integer.parseInt(strPages[i].trim());

                } catch (NumberFormatException nex) {
                    logger.info("ERROR", nex);

                    pages[i] = 0;

                }

            }

        }

        return pages;

    }
}
