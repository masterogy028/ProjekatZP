package sample;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.stage.Stage;

public class Main extends Application {
    public static Stage mainStage;
    @Override
    public void start(Stage primaryStage) throws Exception{
        Keys.getInstance();
        mainStage = primaryStage;
        Parent root = FXMLLoader.load(getClass().getResource("sample.fxml"));
        primaryStage.setTitle("OGALEK en/de/cryptor");
        primaryStage.setScene(new Scene(root, 1000, 700));
        primaryStage.show();
    }


    public static void main(String[] args) {
        launch(args);
    }
}
