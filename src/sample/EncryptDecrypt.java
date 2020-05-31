package sample;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Scanner;


import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;

public class EncryptDecrypt {


    public static byte[] encrypt(final byte[] message, final PGPPublicKey publicKey, final PGPSecretKey secretKey,String passphrase , boolean armored, boolean compress, boolean encrypt, boolean sign )
            throws PGPException
    {
        if(!compress && !armored && !encrypt && !sign) {return message;}
        try
        {
            final ByteArrayInputStream in = new ByteArrayInputStream( message );
            ByteArrayOutputStream startByteArrayOutputStream = new ByteArrayOutputStream();
            OutputStream mainOut;
            final PGPEncryptedDataGenerator generator = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder( SymmetricKeyAlgorithmTags.CAST5 ).setWithIntegrityPacket( true )
                            .setSecureRandom(new SecureRandom() ).setProvider( "BC" ) );

            final PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator( CompressionAlgorithmTags.ZIP );

            PGPSignatureGenerator signatureGenerator = null;


            OutputStream literalOut;

            final PGPLiteralDataGenerator literal = new PGPLiteralDataGenerator();



            final OutputStream pOut;

            if(armored)
                mainOut = new ArmoredOutputStream(startByteArrayOutputStream);
            else
                mainOut = startByteArrayOutputStream;

            if(encrypt) {
                generator.addMethod( new JcePublicKeyKeyEncryptionMethodGenerator( publicKey ).setProvider( "BC" ) );
                mainOut = generator.open(mainOut, 1 << 16);
            }
            if (compress)
            {
                mainOut = comData.open(mainOut);
            }
            if (sign)
            {
                PGPSecretKey pgpSecKey = secretKey;
                String pass = passphrase;
                PGPPrivateKey pgpPrivKey = null;
                try{
                    pgpPrivKey = pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass.toCharArray()));
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("pogresna sifra");
                    return null;
                }
                signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSecKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

                signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

                Iterator it = pgpSecKey.getPublicKey().getUserIDs();
                if (it.hasNext()) {
                    PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

                    spGen.setSignerUserID(false, (String) it.next());
                    signatureGenerator.setHashedSubpackets(spGen.generate());
                }

                signatureGenerator.generateOnePassVersion(false).encode(startByteArrayOutputStream);

            }

            PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
            literalOut = literalDataGenerator.open(mainOut, PGPLiteralData.BINARY, "filename", new Date(), new byte[4096]);

            // Open the input file
            final byte[] buf = new byte[4096];
            for(int len = 0; (len = in.read(buf)) > 0;) {
                literalOut.write(buf, 0, len);
                if(sign)
                signatureGenerator.update(buf, 0, len);
            }
            in.close();
            if(sign)
            signatureGenerator.generate().encode(mainOut);

            literalOut.close();
            literalDataGenerator.close();

            generator.close();
            comData.close();

            return startByteArrayOutputStream.toByteArray();
        }
        catch ( Exception e )
        {
            throw new PGPException( "Error in encrypt", e );
        }
    }

    public static String decrypt( FileInputStream FIS, File FILE) {
        try{
            //get user input
            String inputFileName = FILE.getAbsolutePath();
            //String outputFileName = UserState.instance.getOutputFileName();
            String pass = null;

            InputStream in = FIS;
            in = PGPUtil.getDecoderStream(in);

            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);

            PGPEncryptedDataList enc;

            Object message = pgpF.nextObject();
            while(message != null){
                if(message instanceof PGPEncryptedDataList){
                    enc = (PGPEncryptedDataList) message;

                    Iterator it = enc.getEncryptedDataObjects();
                    PGPPrivateKey sKey = null;
                    PGPPublicKeyEncryptedData pbe = null;

                    while (sKey == null && it.hasNext()) {
                        pbe = (PGPPublicKeyEncryptedData) it.next();
                        String password = Keys.getPassword(pbe.getKeyID());
                        if (password == null) continue;
                        try {
                            PGPSecretKey pgpSecKey = Keys.getInstance().secretKeys.getSecretKey(pbe.getKeyID());
                            if (pgpSecKey == null) return "Decryption failed. Unknown receiver";
                            sKey = pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(password.toCharArray()));

                        }catch (Exception e) {
                            ;
                            return "Wrong password";
                        }
                    }

                    if (sKey == null) {
                        return "Decryption failed. Unknown receiver";
                    }

                    InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
                    pgpF = new JcaPGPObjectFactory(clear);
                    message = pgpF.nextObject();

                    //JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
                    //message = plainFact.nextObject();
                    System.out.println("Encryption successful\n");
                    continue;
                }

                if (message instanceof PGPCompressedData) {
                    PGPCompressedData cData = (PGPCompressedData) message;

                    pgpF = new JcaPGPObjectFactory(cData.getDataStream());
                    message = pgpF.nextObject();

                    //JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
                    //message = pgpFact.nextObject();
                    System.out.println("Compression successful\n");
                    continue;
                }

                if (message instanceof PGPLiteralData) {
                    PGPLiteralData ld = (PGPLiteralData) message;

                    InputStream unc = ld.getInputStream();

                    Scanner s = new Scanner(unc).useDelimiter("\\A");
                    String result = s.hasNext() ? s.next() : "";
                    System.out.println("Message read");
                    return result;
                }

                if(message instanceof PGPOnePassSignatureList){
                    PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) message;
                    PGPOnePassSignature ops = p1.get(0);

                    message = pgpF.nextObject();
                    PGPLiteralData p2 = (PGPLiteralData) message;

                    InputStream dIn = p2.getInputStream();
                    int ch;
                    PGPPublicKey key = Keys.getInstance().findKey(ops.getKeyID());

                    //FileOutputStream out = new FileOutputStream(p2.getFileName());

                    ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);
                    String result = "";
                    while ((ch = dIn.read()) >= 0) {
                        result = result + (char)ch;
                        ops.update((byte) ch);
                    }
                    message = pgpF.nextObject();
                    PGPSignatureList p3 = (PGPSignatureList) message;

                    if (ops.verify(p3.get(0))) {
                        System.out.println("Signature verified by " + key.getUserIDs().next() + "\n");
                        System.out.println("signature verified.");
                        return result;
                    } else {
                        System.out.println("Signature verification failed!\n");
                        //System.out.println("signature verification failed.");
                    }
                    break;
                }
            }

        }catch (Exception e){
            e.printStackTrace();
        }
        return "";
    }
}
