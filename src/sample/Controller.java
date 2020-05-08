package sample;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.stage.Stage;

import java.io.IOException;

public class Controller {
    @FXML
    private Button createKey;
    @FXML
    private Button finishKey;
    @FXML
    private void handleCreateButtonAction(ActionEvent event) throws IOException {
        Stage stage;
        Parent root;
        if(event.getSource() == createKey) {
            stage = (Stage) createKey.getScene().getWindow();
            root = FXMLLoader.load(getClass().getResource("keyCreate.fxml"));
        } else {
            stage = (Stage) finishKey.getScene().getWindow();
            root = FXMLLoader.load(getClass().getResource("sample.fxml"));
        }
        Scene scene = new Scene(root);
        stage.setScene(scene);
        stage.show();

    }
}
