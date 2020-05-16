package sample;
import javafx.collections.ObservableList;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.jcajce.JcaPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

public class Keys {
    public static PGPSecretKeyRingCollection secretKeys;
    public static PGPPublicKeyRingCollection publicKeys;
    private static Keys instance;
    public static String _keysDirPub = System.getProperty("user.dir") + File.separator + "out\\keys\\public";
    public static String _keysDirPriv = System.getProperty("user.dir") + File.separator + "out\\keys\\private";
    static {
        Security.addProvider(new BouncyCastleProvider());
        try {
            publicKeys = new JcaPGPPublicKeyRingCollection(new ArrayList<>());
            secretKeys = new JcaPGPSecretKeyRingCollection(new ArrayList<>());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        }
        try {
                File folder = new File(_keysDirPub);

                for (final File fileEntry : folder.listFiles()) {
                    if (fileEntry.isDirectory()) {
                        //listFilesForFolder(fileEntry);
                    } else {
                        //
                        // System.out.println(fileEntry.getName());
                        InputStream input = new FileInputStream(_keysDirPub+ File.separator+fileEntry.getName());

                        BcPGPObjectFactory factory = new BcPGPObjectFactory(PGPUtil.getDecoderStream(input));
                        Object o = factory.nextObject();
                        if(o == null) continue;
                        if(o instanceof PGPPublicKeyRing) {
                            publicKeys = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeys, (PGPPublicKeyRing) o);
                            //System.out.println(publicKeys.size());
                        }

                    }
                }

                folder = new File(_keysDirPriv);

                for (final File fileEntry : folder.listFiles()) {
                    if (fileEntry.isDirectory()) {
                        //listFilesForFolder(fileEntry);
                    } else {
                        //System.out.println(fileEntry.getName());
                        InputStream input = new FileInputStream(_keysDirPriv+ File.separator+fileEntry.getName());

                        BcPGPObjectFactory factory = new BcPGPObjectFactory(PGPUtil.getDecoderStream(input));
                        Object o = factory.nextObject();
                        if(o == null) continue;
                        if(o instanceof PGPSecretKeyRing) {
                            secretKeys = PGPSecretKeyRingCollection.addSecretKeyRing(secretKeys, (PGPSecretKeyRing)o);
                        }

                    }
                }
                updateTable();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception ee ) {
            ee.printStackTrace();
        }
        // ovo treba da se sredi da radi
    }

    public static void updateTable() {

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

    public static void fillData(ObservableList<KeyModel> data) {
        PGPPublicKeyRing publicRing;
        PGPSecretKeyRing secretRing;
        Iterator<PGPSecretKeyRing> sit = secretKeys.getKeyRings();
        for(Iterator<PGPPublicKeyRing> pit = publicKeys.getKeyRings(); pit.hasNext();) {
            publicRing = pit.next();
            secretRing = sit.next();

            for (Iterator<String> itp = publicRing.getPublicKey().getUserIDs(); itp.hasNext(); ) {
                String userIds = itp.next();
                String ui[] = userIds.split("<|\\>");
                System.out.println(ui[0]);
                data.add(new KeyModel(ui[0], ui[1], Long.toHexString(publicRing.getPublicKey().getKeyID()),publicRing, secretRing));
            }
        }

    }

    public void generateKeyPair(String name, String email, String pass, int dsaSize, int elagamalSize) {
        try {


            KeyPair dsaKeyPair = generateDsaKeyPair(dsaSize);
            KeyPair elGamalKeyPair = generateElGamalKeyPair(elagamalSize);

            PGPKeyRingGenerator pgpKeyRingGen = createPGPKeyRingGenerator(
                    dsaKeyPair,
                    elGamalKeyPair,
                    name + " <" + email + ">",
                    pass.toCharArray()
            );

            File privateKey = new File(_keysDirPriv + File.separator + name+".pgp");
            File publicKey = new File(_keysDirPub + File.separator + name+".pgp");

            PGPPublicKeyRing pgpPubKeyRing = pgpKeyRingGen.generatePublicKeyRing();
            PGPSecretKeyRing pgpSecKeyRing = pgpKeyRingGen.generateSecretKeyRing();

            publicKeys=PGPPublicKeyRingCollection.addPublicKeyRing(publicKeys, pgpPubKeyRing); //Treba ovako da se dodeli kolekciji zato sto je referenca, u f-ciji ne menja kolekciju
            secretKeys=PGPSecretKeyRingCollection.addSecretKeyRing(secretKeys, pgpSecKeyRing); //Ovo treba nekako da exportujemo u neki fajl

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
    public static void deleteKeyring(PGPPublicKeyRing publicRing, PGPSecretKeyRing secretRing, String fileName){

        JcaPGPPublicKeyRingCollection.removePublicKeyRing(publicKeys, publicRing);
        JcaPGPSecretKeyRingCollection.removeSecretKeyRing(secretKeys, secretRing);
        fileName = fileName.split(" ")[0];
        File file = new File(_keysDirPub+"\\"+fileName+".pgp");
        file.delete();
        file = new File(_keysDirPriv+"\\"+fileName+".pgp");
        System.out.println("deleting:"+_keysDirPriv+"\\"+fileName+".pgp"+":");
        if(file.delete())
        {
            System.out.println("File deleted successfully");
        }
        else
        {
            System.out.println("Failed to delete the file");
        }
        // PGPPublicKeyRingCollection.removePublicKeyRing(publicKeys, )

    }
}
