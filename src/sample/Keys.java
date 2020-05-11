package sample;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.util.Date;
import java.util.Iterator;


public class Keys {
    public static PGPSecretKeyRingCollection secretKeys;
    public static PGPPublicKeyRingCollection publicKeys;
    private static Keys instance;
    static {
        Security.addProvider(new BouncyCastleProvider());
//        try {
//            InputStream input = new ByteArrayInputStream(getSecKeyRing());
//            secretKeys = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input), new BcKeyFingerprintCalculator());
//        } catch (IOException e) {
//            e.printStackTrace();
//        } catch (PGPException e) {
//            e.printStackTrace();
//        } catch (Exception ee ) {
//            ee.printStackTrace();
//        }
        // ovo treba da se sredi da radi
    }
    public static Keys getInstance () {
        if(instance!=null)
        return instance;

        instance = new Keys();
        return instance;
    }
    public Keys() {

    }

    public static final void exportSecretKey(PGPKeyRingGenerator pgpKeyRingGen, File keyFile, boolean asciiArmor) throws IOException {
        PGPSecretKeyRing pgpSecKeyRing = pgpKeyRingGen.generateSecretKeyRing();

        if (asciiArmor) {
            ArmoredOutputStream aos = new ArmoredOutputStream(new FileOutputStream(keyFile));
            pgpSecKeyRing.encode(aos);
            aos.close();
        }
        else {
            FileOutputStream fos = new FileOutputStream(keyFile);
            pgpSecKeyRing.encode(fos);
            fos.close();
        }
    }

    public static final void exportPublicKey(PGPKeyRingGenerator pgpKeyRingGen, File keyFile, boolean asciiArmor) throws IOException {
        PGPPublicKeyRing pgpPubKeyRing = pgpKeyRingGen.generatePublicKeyRing();

        if (asciiArmor) {
            ArmoredOutputStream aos = new ArmoredOutputStream(new FileOutputStream(keyFile));
            pgpPubKeyRing.encode(aos);
            aos.close();
        }
        else {
            FileOutputStream fos = new FileOutputStream(keyFile);
            pgpPubKeyRing.encode(fos);
            fos.close();
        }
    }
    public static final KeyPair generateDsaKeyPair(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA", "BC");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }
    public static final KeyPair generateElGamalKeyPair(int keySize) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public void generateKeyPair(String name, String email, String pass, int dsaSize, int elagamalSize) {
        try {
            String keysDirPub = System.getProperty("user.dir") + File.separator + "src/keys/public";
            String keysDirPriv = System.getProperty("user.dir") + File.separator + "src/keys/private";

            KeyPair dsaKeyPair = generateDsaKeyPair(dsaSize);
            KeyPair elGamalKeyPair = generateElGamalKeyPair(elagamalSize);

            PGPKeyRingGenerator pgpKeyRingGen = createPGPKeyRingGenerator(
                    dsaKeyPair,
                    elGamalKeyPair,
                    name + " <" + email + ">",
                    pass.toCharArray()
            );

            File privateKey = new File(keysDirPriv + File.separator + "secret4.pgp");
            File publicKey = new File(keysDirPub + File.separator + "public4.pgp");

            PGPPublicKeyRing pgpPubKeyRing = pgpKeyRingGen.generatePublicKeyRing();
            PGPSecretKeyRing pgpSecKeyRing = pgpKeyRingGen.generateSecretKeyRing();

            PGPPublicKeyRingCollection.addPublicKeyRing(publicKeys, pgpPubKeyRing); //ovo treba da se sredi
            PGPSecretKeyRingCollection.addSecretKeyRing(secretKeys, pgpSecKeyRing); //i jos staticko ucitavanje kljuceva po pokretanju programa

            exportSecretKey(pgpKeyRingGen, privateKey, true);
            exportPublicKey(pgpKeyRingGen, publicKey, true);

            System.out.println("Generated private key: " + privateKey.getAbsolutePath());
            System.out.println("Generated public key: " + publicKey.getAbsolutePath());

            System.out.println(" public key: " + pgpPubKeyRing.getPublicKey().getKeySignatures());
        }
        catch (Exception ex) {
            ex.printStackTrace();
        }
    }
    /**
     *
     * @param dsaKeyPair - the generated DSA key pair
     * @param elGamalKeyPair - the generated El Gamal key pair
     * @param identity - the given identity of the key pair ring
     * @param passphrase - the secret pass phrase to protect the key pair
     * @return a PGP Key Ring Generate with the El Gamal key pair added as sub key
     * @throws Exception
     */
    public static final PGPKeyRingGenerator createPGPKeyRingGenerator(KeyPair dsaKeyPair, KeyPair elGamalKeyPair, String identity, char[] passphrase) throws Exception {

        PGPKeyPair dsaPgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKeyPair, new Date());
        PGPKeyPair elGamalPgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elGamalKeyPair, new Date());
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                dsaPgpKeyPair,
                identity,  /* name<email> -> identity */
                sha1Calc,
                null,
                null,
                new JcaPGPContentSignerBuilder(dsaPgpKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(passphrase)
        );

        keyRingGen.addSubKey(elGamalPgpKeyPair);
        return keyRingGen;
    }
}
