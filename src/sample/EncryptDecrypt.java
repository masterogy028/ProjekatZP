package sample;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;

public class EncryptDecrypt {



    private static String signMessageByteArray(String message,
                                               PGPSecretKey pgpSec, char pass[]) throws IOException,
            NoSuchAlgorithmException, NoSuchProviderException, PGPException,
            SignatureException {
        byte[] messageCharArray = message.getBytes();

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        OutputStream out = encOut;
        out = new ArmoredOutputStream(out);

        // Unlock the private key using the password
        PGPPrivateKey pgpPrivKey = pgpSec
                .extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
                        .setProvider("BC").build(pass));

        // Signature generator, we can generate the public key from the private
        // key! Nifty!
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(pgpSec.getPublicKey()
                        .getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

        sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

        Iterator it = pgpSec.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.setSignerUserID(false, (String) it.next());
            sGen.setHashedSubpackets(spGen.generate());
        }

        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
                PGPCompressedData.ZIP);

        BCPGOutputStream bOut = new BCPGOutputStream(comData.open(out));

        sGen.generateOnePassVersion(false).encode(bOut);

        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY,
                PGPLiteralData.CONSOLE, messageCharArray.length, new Date());

        for (byte c : messageCharArray) {
            lOut.write(c);
            sGen.update(c);
        }

        lOut.close();
        /*
         * while ((ch = message.toCharArray().read()) >= 0) { lOut.write(ch);
         * sGen.update((byte) ch); }
         */
        lGen.close();

        sGen.generate().encode(bOut);

        comData.close();

        out.close();

        return encOut.toString();
    }
    public static byte[] encrypt(final byte[] message, final PGPPublicKey publicKey, boolean armored, boolean compress, boolean encrypt )
            throws PGPException
    {
        try
        {
            final ByteArrayInputStream in = new ByteArrayInputStream( message );
            final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            final PGPLiteralDataGenerator literal = new PGPLiteralDataGenerator();
            final PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator( CompressionAlgorithmTags.ZIP );
            final OutputStream pOut = literal.open( comData.open( bOut ), PGPLiteralData.BINARY, "filename", in.available(), new Date() );
            Streams.pipeAll( in, pOut );
            comData.close();

            final byte[] bytes = bOut.toByteArray();

            final PGPEncryptedDataGenerator generator = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder( SymmetricKeyAlgorithmTags.CAST5 ).setWithIntegrityPacket( true )
                            .setSecureRandom(new SecureRandom() ).setProvider( "BC" ) );

            generator.addMethod( new JcePublicKeyKeyEncryptionMethodGenerator( publicKey ).setProvider( "BC" ) );
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            OutputStream theOut = armored ? new ArmoredOutputStream( out ) : out;
            OutputStream cOut = generator.open( theOut, bytes.length );
            cOut.write( bytes );
            cOut.close();
            theOut.close();
            return out.toByteArray();
        }
        catch ( Exception e )
        {
            throw new PGPException( "Error in encrypt", e );
        }
    }
    public static String encryptMessage(byte[] clearData, HashSet<KeyModel> encKeys, boolean withIntegrityCheck, boolean armor, boolean encrypt, boolean sign, boolean zip)
            throws IOException, PGPException, NoSuchProviderException {

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        // Radix-64
        OutputStream out = encOut;
        if (armor) {
            out = new ArmoredOutputStream(out);
        }
        //


        // ZIP
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream cos = bOut;

        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP);
        cos = comData.open(bOut); // open it with the final
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(cos, PGPLiteralData.BINARY,
                "poruka", clearData.length, // length of clear
                // data
                new Date() // current time
        );
        pOut.write(clearData);
        lData.close();
        comData.close();

        //Encryption
        //PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5, withIntegrityCheck, new SecureRandom(), "BC");
        final PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder( SymmetricKeyAlgorithmTags.AES_256 ).setWithIntegrityPacket( true ).setSecureRandom( new SecureRandom() )
                        .setProvider( "BC" ) );
        cPk.addMethod( new JcePublicKeyKeyEncryptionMethodGenerator( Controller.currentSelected.getPublicRing().getPublicKey() ).setProvider( "BC" ) );

        byte[] bytes = bOut.toByteArray();

        OutputStream cOut = cPk.open(out, bytes.length);

        cOut.write(bytes); // obtain the actual bytes from the compressed stream

        cOut.close();
        //
        out.close();

        return encOut.toString();
    }
}
