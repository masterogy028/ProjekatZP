package sample;

import javafx.beans.property.SimpleStringProperty;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public class KeyModel {
    private SimpleStringProperty name;
    private SimpleStringProperty email;
    private SimpleStringProperty id;
    private PGPPublicKeyRing publicRing;
    private PGPSecretKeyRing secretRing;

    public KeyModel(String n, String e, String i, PGPPublicKeyRing publicRing, PGPSecretKeyRing secretRing) {
        this.name = new SimpleStringProperty(n);
        this.email = new SimpleStringProperty(e);
        this.id = new SimpleStringProperty(i);
        this.publicRing = publicRing;
        this.secretRing = secretRing;

    }
    public KeyModel(SimpleStringProperty name, SimpleStringProperty email, SimpleStringProperty id) {
        this.name = name;
        this.email = email;
        this.id = id;
    }

    public String getName() {
        return name.get();
    }

    public SimpleStringProperty nameProperty() {
        return name;
    }

    public void setName(String name) {
        this.name.set(name);
    }

    public String getEmail() {
        return email.get();
    }

    public SimpleStringProperty emailProperty() {
        return email;
    }

    public void setEmail(String email) {
        this.email.set(email);
    }

    public String getId() {
        return id.get();
    }

    public SimpleStringProperty idProperty() {
        return id;
    }

    public void setId(String id) {
        this.id.set(id);
    }

    public PGPPublicKeyRing getPublicRing() {
        return publicRing;
    }

    public void setPublicRing(PGPPublicKeyRing publicRing) {
        this.publicRing = publicRing;
    }

    public PGPSecretKeyRing getSecretRing() {
        return secretRing;
    }

    public void setSecretRing(PGPSecretKeyRing secretRing) {
        this.secretRing = secretRing;
    }
}
