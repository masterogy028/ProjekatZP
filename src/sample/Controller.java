package sample;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
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
    private Button createKey;
    @FXML
    private Button finishKey;
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
              || passwordField.getText().equals("")|| passwordReTypeField.getText().equals("")) return false;
      return true;
    };
}
