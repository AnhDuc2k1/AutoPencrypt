package extension;

import java.io.File;
import java.io.IOException;

import javax.swing.JCheckBox;
import javax.swing.JTextArea;
import javax.swing.JToggleButton;
import javax.swing.table.DefaultTableModel;

import com.caoccao.javet.exceptions.JavetException;
import com.caoccao.javet.interop.NodeRuntime;
import com.caoccao.javet.interop.V8Host;
import com.caoccao.javet.node.modules.NodeModuleModule;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import extension.Logs.LogEntry;
import extension.Logs.LogManager;

public class CustomHttpHandler implements HttpHandler {
    private MontoyaApi api;
    private JTextArea encryptionScript, decryptionScript;
    private JToggleButton activateButton;
    private DefaultTableModel tableModel;
    private JCheckBox inScopeCheckBox;
    private LogManager logManager;

    private HttpRequest originalHttpRequest;
    private HttpResponse originalHttpResponse;

    private HttpRequest modifiedHttpRequest;
    private HttpResponse modifiedHttpResponse;

    public CustomHttpHandler(MontoyaApi api, JTextArea encryptionScript, JTextArea decryptionScript,
            JToggleButton activateButton, DefaultTableModel tableModel,
            JCheckBox inScopeCheckBox, LogManager logManager) {
        this.api = api;
        this.encryptionScript = encryptionScript;
        this.decryptionScript = decryptionScript;
        this.tableModel = tableModel;
        this.activateButton = activateButton;
        this.inScopeCheckBox = inScopeCheckBox;
        this.logManager = logManager;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (this.activateButton.isSelected()) {
            String encryptionScript = this.encryptionScript.getText().trim();
            this.modifiedHttpRequest = requestToBeSent;
            if (!encryptionScript.isEmpty()) {
                if (this.inScopeCheckBox.isSelected()) {
                    if (!this.api.scope().isInScope(requestToBeSent.url())) {
                        return RequestToBeSentAction.continueWith(requestToBeSent);
                    }
                }
                try {
                    try (NodeRuntime nodeRuntime = loadLibrary(V8Host.getNodeInstance().createV8Runtime())) {

                        nodeRuntime.getGlobalObject().set("request_body", requestToBeSent.bodyToString());
                        nodeRuntime.getExecutor("request_body = JSON.parse(request_body);").executeVoid();
                        nodeRuntime.getExecutor(encryptionScript).executeVoid();

                        try {
                            nodeRuntime.getExecutor("encrypted_request_body = JSON.stringify(encrypted_request_body);")
                                    .executeVoid();

                            String encryptedRequestBody = nodeRuntime.getGlobalObject().get("encrypted_request_body")
                                    .toString();

                            HttpRequest modifiedRequest = requestToBeSent.withBody(encryptedRequestBody);

                            this.originalHttpRequest = modifiedRequest;

                            return RequestToBeSentAction.continueWith(modifiedRequest);
                        } catch (Exception e) {
                            this.api.logging().logToError(e.getMessage());
                            return RequestToBeSentAction.continueWith(requestToBeSent);
                        }
                    }

                } catch (Exception e) {
                    this.api.logging().logToError(e.getMessage());
                }
            }
        }
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (this.activateButton.isSelected()) {
            String decryptionScript = this.decryptionScript.getText().trim();

            if (!decryptionScript.isEmpty()) {

                try {
                    try (NodeRuntime nodeRuntime = loadLibrary(V8Host.getNodeInstance().createV8Runtime())) {

                        nodeRuntime.getGlobalObject().set("response_body", responseReceived.bodyToString().toString());
                        nodeRuntime.getExecutor("response_body = JSON.parse(response_body);").executeVoid();
                        nodeRuntime.getExecutor(decryptionScript).executeVoid();

                        this.originalHttpResponse = responseReceived;

                        try {
                            String decryptedResponseBody = nodeRuntime.getGlobalObject().get("decrypted_response_body")
                                    .toString();

                            HttpResponse modifiedResponse = responseReceived.withBody(decryptedResponseBody);

                            this.modifiedHttpResponse = modifiedResponse;

                            if (this.inScopeCheckBox.isSelected()) {
                                if (this.api.scope().isInScope(this.originalHttpRequest.url())) {
                                    LogEntry newLogEntry = new LogEntry(
                                            logManager.getLogTableModel().getLogCount() + 1,
                                            this.originalHttpRequest, this.originalHttpResponse,
                                            this.modifiedHttpRequest,
                                            this.modifiedHttpResponse);

                                    logManager.addEntry(newLogEntry);
                                    return ResponseReceivedAction.continueWith(modifiedResponse);
                                }
                            } else if (!this.inScopeCheckBox.isSelected()) {
                                LogEntry newLogEntry = new LogEntry(
                                        logManager.getLogTableModel().getLogCount() + 1,
                                        this.originalHttpRequest, this.originalHttpResponse, this.modifiedHttpRequest,
                                        this.modifiedHttpResponse);

                                logManager.addEntry(newLogEntry);
                                return ResponseReceivedAction.continueWith(modifiedResponse);
                            }
                        } catch (Exception e) {
                            this.api.logging().logToError(e.getMessage());
                            return ResponseReceivedAction.continueWith(responseReceived);
                        }
                    }

                } catch (Exception e) {
                    this.api.logging().logToError(e.getMessage());
                }
            }
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private NodeRuntime loadLibrary(NodeRuntime nodeRuntime) throws IOException, JavetException {
        int rowCount = this.tableModel.getRowCount();
        int columnCount = this.tableModel.getColumnCount();

        for (int row = 0; row < rowCount; row++) {
            for (int column = 0; column < columnCount; column++) {
                Object libraryPath = tableModel.getValueAt(row, column);
                File libraryFile = new File(libraryPath.toString());

                nodeRuntime.getNodeModule(NodeModuleModule.class).setRequireRootDirectory(libraryFile);
            }
        }
        return nodeRuntime;
    }
}