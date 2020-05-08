package sample;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;

public class Keys {
    public static PGPSecretKeyRingCollection secretKeys;
    public static PGPPublicKeyRingCollection publicKeys;
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

    public void generateKeyPair() {
        try {
            String keysDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/keys";

            KeyPair dsaKeyPair = generateDsaKeyPair(1024);
            KeyPair elGamalKeyPair = generateElGamalKeyPair(1024);

            PGPKeyRingGenerator pgpKeyRingGen = createPGPKeyRingGenerator(
                    dsaKeyPair,
                    elGamalKeyPair,
                    "Greg House <g.house@gmail.com>",
                    "TestPass12345!".toCharArray()
            );

            File privateKey = new File(keysDir + File.separator + "secret4.asc");
            File publicKey = new File(keysDir + File.separator + "public4.asc");

            exportSecretKey(pgpKeyRingGen, privateKey, true);
            exportPublicKey(pgpKeyRingGen, publicKey, true);

            System.out.println("Generated private key: " + privateKey.getAbsolutePath());
            System.out.println("Generated public key: " + publicKey.getAbsolutePath());
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
