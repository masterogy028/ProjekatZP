package sample;

import javafx.beans.Observable;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.VBox;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import javax.swing.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.security.NoSuchProviderException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.ResourceBundle;

public class Controller implements Initializable {
    @FXML
    private TextArea myTextAreaMessage;
    @FXML
    private TextArea myResultMessage;
    @FXML
    private Button EncryptButton;
    @FXML
    private Button DecryptButton;

    @FXML
    private Label selectPrivatekeyLabel;
    @FXML
    private ComboBox selectPrivateKeyComboBox;
    @FXML
    private TextField passphraseTextField;
    @FXML
    private CheckBox radixCheckBox;
    @FXML
    private CheckBox EncryptCheckBox;
    @FXML
    private CheckBox ZipCheckBox;
    @FXML
    private CheckBox SignatureCheckBox;

    @FXML
    private VBox myEncVBox;
    @FXML
    private Label selectedKeysLabel;
    @FXML
    private Label toSelectedKeysLabel;
    @FXML
    private Label wrongPasswordLabel;
    @FXML
    private Label noKeySelectedLabel;
    @FXML
    private TextField nameField;
    @FXML
    private TextField emailField;
    @FXML
    private TextField passwordField;
    @FXML
    private TextField passwordReTypeField;
    @FXML
    private TableView<KeyModel> myTable;
    @FXML
    private TableView<KeyModel> myTableEnc;
    @FXML
    private TableColumn<KeyModel, String> col_name;
    @FXML
    private TableColumn<KeyModel, String> col_id;
    @FXML
    private TableColumn<KeyModel, String> col_email;
    @FXML
    private TableColumn<KeyModel, String> col_name_enc;
    @FXML
    private TableColumn<KeyModel, String> col_id_enc;
    @FXML
    private TableColumn<KeyModel, String> col_email_enc;
    private ObservableList <KeyModel> data;
    @FXML
    private RadioButton dsa1024;
    @FXML
    private RadioButton dsa2048;
    @FXML
    private RadioButton elgamal2048;
    @FXML
    private RadioButton elgamal1024;
    @FXML
    private RadioButton elgamal4096;
    private HashSet<KeyModel> selected;
    private int dsaSize = 0;
    private int elagamalSize = 0;
    @FXML
    private Button createKey;
    @FXML
    private Button deleteKey;
    @FXML
    private Button finishKey;
    private Scene scene;
    public static KeyModel currentSelected = null;
    public static KeyModel currentSelectedPrivateKey = null;



    @FXML
    private void handleDsaSizeRadiobox(ActionEvent event) throws IOException {
        if(event.getSource() == dsa1024) {
            dsaSize =1024;
        }
        if(event.getSource() == dsa2048) {
            dsaSize = 2048;
        }
        if(event.getSource() == elgamal1024) {
            elagamalSize = 1024;
        }
        if(event.getSource() == elgamal2048) {
            elagamalSize = 2048;
        }
        if(event.getSource() == elgamal4096) {
            elagamalSize = 4096;
        }
    }
    @FXML
    private void handleCreateButtonAction(ActionEvent event) throws IOException {
        Stage stage;
        Parent root;
        Boolean allGood = true;

        if(event.getSource() == createKey) {
            stage = (Stage) createKey.getScene().getWindow();
            root = FXMLLoader.load(getClass().getResource("keyCreate.fxml"));
        } else {
            allGood = finishCreation();
            stage = (Stage) finishKey.getScene().getWindow();
            root = FXMLLoader.load(getClass().getResource("sample.fxml"));
        }
        if(!allGood) return;
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();

    }
    @FXML
    private void handleEncryptButtonAction(ActionEvent event) throws IOException {

        if(selected.size() == 0 && EncryptCheckBox.selectedProperty().getValue()) return;
        if(SignatureCheckBox.selectedProperty().getValue() && currentSelectedPrivateKey == null) return;
        FileChooser fc = new FileChooser();
        FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("PGP files (*.pgp)", "*.pgp");
        fc.getExtensionFilters().add(extFilter);

        File file = fc.showSaveDialog(Main.mainStage);

        try {
            FileOutputStream fos = new FileOutputStream(file);
            PGPPublicKey masterKey = null;
            PGPPublicKey subKey = null;
            if(EncryptCheckBox.selectedProperty().getValue()) {
                Iterator<PGPPublicKey> it = selected.iterator().next().getPublicRing().getPublicKeys();
                masterKey =  it.next();
                subKey =  it.next();

            }

            byte array[];

            System.out.println(masterKey.getKeyID()+"\n" + subKey.getKeyID() + "\n" + currentSelectedPrivateKey.getSecretRing().getSecretKey().getKeyID()+ "\n");

            if(currentSelectedPrivateKey!=null)
                array  = EncryptDecrypt.encrypt(myTextAreaMessage.getText().getBytes(),myTextAreaMessage.getText(), subKey,currentSelectedPrivateKey.getSecretRing().getSecretKey(), passphraseTextField.getText(),
                    radixCheckBox.isSelected(), ZipCheckBox.isSelected() , EncryptCheckBox.isSelected(), SignatureCheckBox.isSelected(), file.getName());
            else
                array = EncryptDecrypt.encrypt(myTextAreaMessage.getText().getBytes(),myTextAreaMessage.getText(),  subKey,null, passphraseTextField.getText(),
                     radixCheckBox.isSelected(), ZipCheckBox.isSelected() , EncryptCheckBox.isSelected(), SignatureCheckBox.isSelected(), file.getName());
            if(array == null) {noKeySelectedLabel.setText("Wrong passphrase for private key!"); noKeySelectedLabel.setVisible(true); return;}
            fos.write(array);
            fos.close();

        } catch (PGPException e) {
            e.printStackTrace();
        }

    }
    @FXML
    private void handleDecryptButtonAction(ActionEvent event) throws IOException {

        FileChooser fc = new FileChooser();
        FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("PGP files (*.pgp)", "*.pgp");
        fc.getExtensionFilters().add(extFilter);

        File file = fc.showOpenDialog(Main.mainStage);

        FileInputStream fos = new FileInputStream(file);
        try {
            myResultMessage.setText(EncryptDecrypt.decrypt( fos, file));
        } catch (Exception e) {
            e.printStackTrace();
        }


    }
    @FXML
    private void handleDeleteKeyButtonAction(ActionEvent event) throws IOException {
        if(currentSelected != null){
            final Stage dialog = new Stage();
            dialog.initModality(Modality.APPLICATION_MODAL);
            dialog.initOwner(Main.mainStage);
            VBox dialogVbox = new VBox(20);
            dialogVbox.getChildren().add(new Text("Enter password"));
            final TextField passField = new TextField();
            dialogVbox.getChildren().add(passField);
            Button finishDelete = new Button("Delete key");
            finishDelete.setOnAction(new EventHandler<ActionEvent>() {
                @Override
                public void handle(ActionEvent event) {
                    // Keys.checkPassFor(passField.getText(), currentSelected);
                    try {
                        currentSelected.getSecretRing().getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passField.getText().toCharArray()));
                    } catch (PGPException e) {
                        return;
                    }
                    Keys.deleteKeyring(currentSelected.getPublicRing(), currentSelected.getSecretRing(), currentSelected.getName());
                    data.remove(currentSelected);
                    currentSelected = null;
                    deleteKey.setDisable(true);
                    dialog.close();
                }
            });
            dialogVbox.getChildren().add(finishDelete);

            Scene dialogScene = new Scene(dialogVbox, 300, 200);
            dialog.setScene(dialogScene);
            dialog.show();

//            Keys.deleteKeyring(currentSelected.getPublicRing(), currentSelected.getSecretRing(), currentSelected.getName());
//            data.remove(currentSelected);
//            currentSelected = null;
//            deleteKey.setDisable(true);
        }
    }
    private Boolean finishCreation(){
      if (nameField.getText() == null || nameField.getText().equals("") || emailField.getText().equals("")
              || passwordField.getText().equals("")|| passwordReTypeField.getText().equals("") || elagamalSize == 0 || dsaSize == 0) return false;
      // provera da se implementira
      Keys.getInstance().generateKeyPair(nameField.getText(), emailField.getText(), passwordField.getText(), dsaSize, elagamalSize);
      return true;
    };

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        selected = new HashSet<>();
        data = FXCollections.observableArrayList();
        Keys.fillData(data);
        if(col_id != null){

            col_id.setCellValueFactory(new PropertyValueFactory<KeyModel, String>("Id"));
            col_email.setCellValueFactory(new PropertyValueFactory<KeyModel, String>("Email"));
            col_name.setCellValueFactory(new PropertyValueFactory<KeyModel, String>("Name"));

            myTable.setItems(data);
            myTable.getSelectionModel().selectedItemProperty().addListener((Observable observable) -> {
                        int index = myTable.getSelectionModel().getSelectedIndex();
                        KeyModel key = myTable.getItems().get(index);
                        currentSelected = key;
                        deleteKey.setDisable(false);
                        System.out.println(key.getName());

                    }
            );
        }
        if(col_id_enc != null){

            col_id_enc.setCellValueFactory(new PropertyValueFactory<KeyModel, String>("Id"));
            col_email_enc.setCellValueFactory(new PropertyValueFactory<KeyModel, String>("Email"));
            col_name_enc.setCellValueFactory(new PropertyValueFactory<KeyModel, String>("Name"));

            myTableEnc.setItems(data);
            myTableEnc.getSelectionModel().selectedItemProperty().addListener((Observable observable) -> {
                        int index = myTableEnc.getSelectionModel().getSelectedIndex();
                        KeyModel key = myTableEnc.getItems().get(index);
                        if(!selected.contains(key))
                            selected.add(key);
                        else
                            selected.remove(key);
                        if(selected.size() == 0) {
                            noKeySelectedLabel.setVisible(true);
                            selectedKeysLabel.setVisible(false);
                            toSelectedKeysLabel.setVisible(false);
                        }
                        else {
                            toSelectedKeysLabel.setVisible(true);
                            noKeySelectedLabel.setVisible(false);
                            selectedKeysLabel.setVisible(true);
                            String keysString = "";
                            for (KeyModel keyModel: selected) {
                                keysString = keysString + "\n" + keyModel.getName();
                            }
                            selectedKeysLabel.setText(keysString);
                        }


                        System.out.println(key.getName());
                        System.out.println("selected: " + selected.size());

                    }
            );
            selectPrivateKeyComboBox.setItems(data);
            selectPrivateKeyComboBox.valueProperty().addListener((obs, oldVal, newVal) ->
                    currentSelectedPrivateKey = (KeyModel) selectPrivateKeyComboBox.getValue());

            SignatureCheckBox.setOnAction(new EventHandler<ActionEvent>() {
                @Override
                public void handle(ActionEvent event) {
                    CheckBox sig = (CheckBox) event.getSource();
                    // System.out.println(sig.selectedProperty().get());
                    if(sig.selectedProperty().get()) {
                        passphraseTextField.setDisable(false);
                        selectPrivateKeyComboBox.setVisible(true);
                        selectPrivatekeyLabel.setVisible(true);
                    } else {
                        passphraseTextField.setDisable(true);
                        selectPrivateKeyComboBox.setVisible(false);
                        selectPrivatekeyLabel.setVisible(false);
                    }
                }
            });
        }

    }

}
