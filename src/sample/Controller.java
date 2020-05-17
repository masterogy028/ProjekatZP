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
import javafx.stage.Modality;
import javafx.stage.Stage;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.io.IOException;
import java.net.URL;
import java.util.ResourceBundle;

public class Controller implements Initializable {
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
    private TableColumn<KeyModel, String> col_name;
    @FXML
    private TableColumn<KeyModel, String> col_id;
    @FXML
    private TableColumn<KeyModel, String> col_email;
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

    private int dsaSize = 0;
    private int elagamalSize = 0;
    @FXML
    private Button createKey;
    @FXML
    private Button deleteKey;
    @FXML
    private Button finishKey;
    private Scene scene;
    private KeyModel currentSelected;

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
                            deleteKey.setDisable(false); // ovo bi trebalo da kada se selektuje red u tabeli promeni enable property deleteButton-a ali
                            System.out.println(key.getName()); //  ne radi iz nekog razloga, tj.  ne ulazi se u ovu funkciju

                        }
                );

            }


    }

}
