import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.CrlClientOnline;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import java.io.File;
import java.io.InputStream;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class PDFSigningService extends FileSigningServices {

    public void sign(PdfReader reader, FileOutputStream os, Certificate[] chain, PrivateKey pk, String provider, int llx, int lly, int urx, int ury, String reason, String location, int pagesToSign, java.security.cert.X509Certificate cert) {
        try {

            System.out.println("page no sign ==> " + pagesToSign);
            BouncyCastleProvider bc = new BouncyCastleProvider();
            Security.addProvider(bc);
            PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();

            appearance.setReason(reason);
            appearance.setLocation(location);
            appearance.setAcro6Layers(false);
            appearance.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);
            appearance.setSignatureCreator("test");
            appearance.setVisibleSignature(new Rectangle(llx, lly, urx, ury), pagesToSign, pagesToSign + "test" + System.currentTimeMillis()); //sign on 1st page corner
            ExternalDigest digest = new BouncyCastleDigest();
            ExternalSignature signature = new PrivateKeySignature(pk, DigestAlgorithms.SHA1, provider);
            MakeSignature.signDetached(appearance, digest, signature, chain, null, null, null, 0, MakeSignature.CryptoStandard.CMS);

        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }

    public static String signPDFPage(PdfReader reader, FileOutputStream output, String provider, PrivateKey key, Certificate[] chain, int pageToShowSign, int llx, int lly, int urx, int ury, String reason, String loctaion, java.security.cert.X509Certificate cert) {
        try {
            System.out.println("Singing please wait...");
            PDFSigningService allPages = new PDFSigningService();
            allPages.sign(reader, output, chain, key, provider, llx, lly, urx, ury, reason, loctaion, pageToShowSign, cert);
            return "success";
        } catch (Exception exception) {
            exception.printStackTrace();
            return "";
        }
    }

    public static void main(String[] args) throws Exception {
        args = new String[7];
        args[0] = "D:\\test.pfx";
        args[1] = "123456";
        args[2] = "C:\\Users\\Documents\\test.pdf";
        args[3] = "C:\\Users\\\Documents\\Sampe PDF file_Out.pdf";
        args[4] = "1";
        args[5] = "PDF Reason";
        args[6] = "PDF Location";

        if (args.length == 7) {
            for (int a = 0; a < 1; a++) {
                KeyStore ks = loadKeyStore("PKCS12", args[0], args[1]);
                String alias = getFirstAlias(ks);
                PrivateKey pk = getPrivateKey(ks, alias, args[1]);
                Certificate[] chain = ks.getCertificateChain(alias);
                java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) ks.getCertificate(alias);
                PDFSigningService pDFSigningService = new PDFSigningService();
                PdfReader reader = new PdfReader(args[2]);
                FileOutputStream fos = new FileOutputStream(args[3]);
                int llx = 5;//100;
                int lly = 10; //100;
                int urx = 80;//150;
                int ury = 650;//250;
                String pageNo = args[4];
                int totPages = 0;
                int showSigOnPages = Integer.parseInt(args[4] + "".trim());

                pDFSigningService.signPDFPage(reader, fos, ks.getProvider().getName(), pk, chain, showSigOnPages, llx, lly, ury, urx, args[5], args[6], cert);
                System.out.println("File signed");
            }
        } else {
            System.err.println("usage <PFX FILE PATH> , <PFX PASSWORD> , <INPUT FILE FOR TIME STAMP>, <OUTPUT FILE FOR TIME STAMP>");
        }
        System.exit(0);
    }

}
