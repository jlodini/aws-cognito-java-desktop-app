package com.amazonaws.sample.cognito.ui;

import com.amazonaws.sample.cognito.service.CognitoUser;
import com.amazonaws.sample.cognito.service.CognitoJWTParser;
import com.amazonaws.services.cognitoidentity.model.Credentials;
import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.stage.Stage;
import org.json.JSONObject;

public class MainForm extends Application {

    public static void main(String[] args) {
        launch(args);
    }

    static void ShowUserBuckets(Credentials credentails) {

        CognitoUser helper = new CognitoUser();
        String message = helper.ListBucketsForUser(credentails);

        BucketListForm.display("Cognito -  Returned Credentials", message);

    }

    @Override
    public void start(Stage primaryStage) {

        CognitoUser helper = new CognitoUser();
        Stage window;
        Button signup_button;
        Button signin_button;
        Button forgot_pswd_button;

        window = primaryStage;
        window.setTitle("Cognito POC");
        VBox vb = new VBox();
        vb.setPadding(new Insets(10, 50, 50, 50));
        vb.setSpacing(10);

        // Username field
        TextField Username = new TextField();
        Label username_label = new Label("Username:");
        HBox hbu = new HBox();
        hbu.getChildren().addAll(username_label, Username);
        hbu.setSpacing(10);

        // password field
        TextField Password = new PasswordField();
        Label password_label = new Label("Password:");
        HBox hbp = new HBox();
        hbp.getChildren().addAll(password_label, Password);
        hbp.setSpacing(10);

        signup_button = new Button("Sign-Up");
        vb.setPadding(new Insets(10, 50, 50, 50));
        vb.setSpacing(10);
        Label lbl = new Label("");
        Image image = new Image(getClass().getClassLoader().getResourceAsStream("ryanair.png"));
        lbl.setGraphic(new ImageView(image));
        lbl.setTextFill(Color.web("#0076a3"));
        lbl.setFont(Font.font("Amble CN", FontWeight.BOLD, 24));
        vb.getChildren().add(lbl);

        signup_button.setOnAction(e -> {
            boolean result = ConfirmBox.display("Cognito Poc", "Sign-Up Form");
            System.out.println(result);
        });

        signin_button = new Button("Sign-In");
        Label auth_message = new Label("");

        signin_button.setOnAction((ActionEvent e) -> {
            String result = null;
            try {
                result = helper.ValidateUser(Username.getText(), Password.getText());
            } catch (Exception e1) {
                e1.printStackTrace();
            }
            if (result != null) {
                System.out.println("User is authenticated:" + result);
                auth_message.setText("User is authenticated");
                JSONObject payload = CognitoJWTParser.getPayload(result);
                String provider = payload.get("iss").toString().replace("https://", "");

                Credentials credentails = helper.GetCredentials(provider, result);

                ShowUserBuckets(credentails);
            } else {
                System.out.println("Username/password is invalid");
                auth_message.setText("Username/password is invalid");
            }
        });

        forgot_pswd_button = new Button("Forgot Password?");
        forgot_pswd_button.setOnAction(e -> {
            boolean result = ForgotPassword.display("Cognito POC", "Forgot password");
            System.out.println(result);
        });

        signup_button.setMaxWidth(142);
        signin_button.setMaxWidth(142);
        forgot_pswd_button.setMaxWidth(142);

        Hyperlink hl = new Hyperlink("Cognito Hosted UI");
        hl.setTooltip(new Tooltip(helper.GetHostedSignInURL()));
        hl.setOnAction((ActionEvent event) -> {
//            Hyperlink h = (Hyperlink) event.getTarget();
//            String s = h.getTooltip().getText();
//            this.getHostServices().showDocument(s);
//            event.consume();
            HostedUI.display("Cognito POC", helper.GetHostedSignInURL());

        });

        /* StackPane layout = new StackPane(); */
        vb.getChildren().addAll(hbu, hbp, signin_button, signup_button, forgot_pswd_button, auth_message, hl);
        vb.setAlignment(Pos.CENTER);

        Scene scene = new Scene(vb, 400, 500);
        window.setScene(scene);
        window.show();
    }

}
