package sample;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TextField;
import javafx.stage.Stage;

import java.io.IOException;

public class Controller {
    @FXML
    private TextField nameField;
    @FXML
    private TextField emailField;
    @FXML
    private TextField passwordField;
    @FXML
    private TextField passwordReTypeField;

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
    private Button finishKey;
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
            stage = (Stage) finishKey.getScene().getWindow();
            root = FXMLLoader.load(getClass().getResource("sample.fxml"));
            allGood = finishCreation();
        }
        if(!allGood) return;
        Scene scene = new Scene(root);
        stage.setScene(scene);
        stage.show();

    }
    private Boolean finishCreation(){
        //System.out.println("res: " + nameField.getText());
      if (nameField.getText() == null || nameField.getText().equals("") || emailField.getText().equals("")
              || passwordField.getText().equals("")|| passwordReTypeField.getText().equals("") || elagamalSize == 0 || dsaSize == 0) return false;
      Keys.getInstance().generateKeyPair(nameField.getText(), emailField.getText(), passwordField.getText(), dsaSize, elagamalSize);
      return true;
    };
}
