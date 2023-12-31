package extension;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import extension.Logs.LogEntry;
import extension.Logs.LogManager;
import extension.Logs.LogTableModel;

public class AutoPencrypt implements IBurpExtender, BurpExtension, IMessageEditorController {

  private static IBurpExtenderCallbacks callbacks;
  private MontoyaApi montoyaApi;

  public static final int TEXT_HEIGHT = new JTextField().getPreferredSize().height;
  public static final Dimension buttonDimension = new Dimension(130, TEXT_HEIGHT);
  public static final Dimension paneDimension = new Dimension(500, 100);
  private static final Font defaultFont = new Font("Courier New", Font.BOLD, 14);

  private static JSplitPane mainTabbedPane;
  private JSplitPane mainSplitPane;
  private JTabbedPane viewSplitPane;
  private JSplitPane actionSplitPane;

  private JPanel configurationPane;
  private JTabbedPane configurationTabbedPane;

  private JTextArea encryptionScript = new JTextArea(30, 100);
  private JTextArea decryptionScript = new JTextArea(30, 100);
  private JToggleButton enableButton = new JToggleButton("Enable Extension");
  private JButton clearLogButton = new JButton("Clear logs");
  private DefaultTableModel tableModel = new DefaultTableModel(new Object[] { "File Path" }, 0);
  private JCheckBox inScopeCheckBox = new JCheckBox("In Scope Request");

  private JSplitPane encryptedRequestResponseSplitPane;
  private JSplitPane decryptedRequestResponseSplitPane;

  private LogTable logTable;
  private static LogManager logManager;

  private IMessageEditor encryptedRequestViewer;
  private IMessageEditor encryptedResponseViewer;
  private IMessageEditor decryptedRequestViewer;
  private IMessageEditor decryptedResponseViewer;

  private JPanel encryptedRequestPanel;
  private JPanel encryptedResponsePanel;
  private JPanel decryptedRequestPanel;
  private JPanel decryptedResponsePanel;

  byte[] encryptedRequest;
  byte[] encryptedResponse;
  byte[] decryptedRequest;
  byte[] decryptedResponse;

  private JLabel encryptedRequestLabel;
  private JLabel encryptedResponseLabel;
  private JLabel decryptedRequestLabel;
  private JLabel decryptedResponseLabel;

  private HttpRequest currentEncryptedRequest;
  private HttpResponse currentEncryptedResponse;
  private HttpRequest currentDecryptedRequest;
  private HttpResponse currentDecryptedResponse;

  @Override
  public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

    AutoPencrypt.callbacks = callbacks;

    logManager = new LogManager();
    logTable = new LogTable(logManager.getLogTableModel());

    createUI();
    mainTabbedPane = mainSplitPane;
  }

  @Override
  public void initialize(MontoyaApi api) {
    this.montoyaApi = api;
    this.montoyaApi.extension().setName("AutoPencrypt");
    api.userInterface().registerSuiteTab("AutoPencrypt", mainTabbedPane);
    montoyaApi.http().registerHttpHandler(createHandlerWithScript(api));
    api.logging().logToOutput(
        "AutoPencrypt Extension is loaded successful!\nVersion 1.1\nCreated by Tran Anh Duc-B19DCAT047\nD19AT-PTIT");
  }

  private void createUI() {
    GridBagConstraints c;

    mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

    encryptedRequestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
    decryptedRequestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

    configurationTabbedPane = new JTabbedPane();

    enableButton.addChangeListener(e -> {
      if (enableButton.isSelected()) {
        enableButton.setText("Disable Extension");
      } else {
        enableButton.setText("Enable Extension");
      }
    });

    clearLogButton.addActionListener(e -> {
      logManager.clearLog();

      encryptedRequest = null;
      encryptedResponse = null;
      decryptedRequest = null;
      decryptedResponse = null;

      currentEncryptedRequest = null;
      currentEncryptedResponse = null;
      currentDecryptedRequest = null;
      currentDecryptedResponse = null;
    });
    Dimension enableButtonDimension = new Dimension(150, TEXT_HEIGHT);
    enableButton.setPreferredSize(enableButtonDimension);
    enableButton.setMaximumSize(enableButtonDimension);
    enableButton.setMinimumSize(enableButtonDimension);

    Dimension clearLogDimension = new Dimension(150, TEXT_HEIGHT);
    clearLogButton.setPreferredSize(clearLogDimension);
    clearLogButton.setMaximumSize(clearLogDimension);
    clearLogButton.setMinimumSize(clearLogDimension);

    configurationPane = new JPanel();
    configurationPane.setLayout(new GridBagLayout());
    configurationPane.setMinimumSize(paneDimension);
    configurationPane.setPreferredSize(paneDimension);
    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.NORTHWEST;

    JPanel toggleButtonPanel = new JPanel();
    toggleButtonPanel.add(enableButton);
    toggleButtonPanel.add(clearLogButton);

    configurationPane.add(toggleButtonPanel, c);
    c.fill = GridBagConstraints.BOTH;
    c.weightx = 1;
    c.weighty = 1;
    c.gridy = 1;

    configurationPane.add(configurationTabbedPane, c);

    JTabbedPane tabbedPane = new JTabbedPane();
    tabbedPane.add("Encryption Script", createTabPanel(this.encryptionScript));
    tabbedPane.add("Decryption Script", createTabPanel(this.decryptionScript));
    tabbedPane.add("Import Libary", createSettingTabPanel(this.tableModel));

    JPanel optionsTabPane = new JPanel();
    optionsTabPane.setLayout(new GridLayout(5, 1));
    optionsTabPane.add(this.inScopeCheckBox);

    configurationTabbedPane.add("Configurations", tabbedPane);
    configurationTabbedPane.add("Options", optionsTabPane);

    logTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
      @Override
      public Component getTableCellRendererComponent(
          JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        return c;
      }
    });

    logTable.setAutoCreateRowSorter(true);
    logTable.getColumnModel().getColumn(0).setPreferredWidth(5);
    logTable.getColumnModel().getColumn(1).setPreferredWidth(10);
    logTable.getColumnModel().getColumn(2).setPreferredWidth(200);
    logTable.getColumnModel().getColumn(3).setPreferredWidth(20);
    logTable.getColumnModel().getColumn(4).setPreferredWidth(20);
    logTable.getColumnModel().getColumn(5).setPreferredWidth(20);

    JScrollPane logTableScrollPane = new JScrollPane(logTable);
    logTableScrollPane.setMinimumSize(paneDimension);
    logTableScrollPane.setPreferredSize(paneDimension);

    viewSplitPane = new JTabbedPane();
    viewSplitPane.setMinimumSize(paneDimension);
    viewSplitPane.addChangeListener(e -> {
      switch (viewSplitPane.getSelectedIndex()) {
        case 0:
          updateEncryptedRequestResponseViewer();
          break;
        default:
          updateDecryptedRequestResponseViewer();
          break;
      }
    });

    encryptedRequestViewer = callbacks.createMessageEditor(this, false);
    encryptedResponseViewer = callbacks.createMessageEditor(this, false);
    decryptedRequestViewer = callbacks.createMessageEditor(this, false);
    decryptedResponseViewer = callbacks.createMessageEditor(this, false);

    encryptedRequestLabel = new JLabel("Request");
    encryptedResponseLabel = new JLabel("Response");
    decryptedRequestLabel = new JLabel("Request");
    decryptedResponseLabel = new JLabel("Response");

    encryptedRequestLabel.setForeground(new Color(0xff6633));
    encryptedResponseLabel.setForeground(new Color(0xff6633));
    decryptedRequestLabel.setForeground(new Color(0xff6633));
    decryptedResponseLabel.setForeground(new Color(0xff6633));

    encryptedRequestLabel.setFont(defaultFont);
    encryptedResponseLabel.setFont(defaultFont);
    decryptedRequestLabel.setFont(defaultFont);
    decryptedResponseLabel.setFont(defaultFont);

    encryptedRequestPanel = new JPanel();
    encryptedResponsePanel = new JPanel();

    decryptedRequestPanel = new JPanel();
    decryptedResponsePanel = new JPanel();

    encryptedRequestPanel.setLayout(new BoxLayout(encryptedRequestPanel, BoxLayout.PAGE_AXIS));
    encryptedResponsePanel.setLayout(new BoxLayout(encryptedResponsePanel, BoxLayout.PAGE_AXIS));

    decryptedRequestPanel.setLayout(new BoxLayout(decryptedRequestPanel, BoxLayout.PAGE_AXIS));
    decryptedResponsePanel.setLayout(new BoxLayout(decryptedResponsePanel, BoxLayout.PAGE_AXIS));

    encryptedRequestPanel.add(encryptedRequestLabel);
    encryptedRequestPanel.add(encryptedRequestViewer.getComponent());
    encryptedRequestPanel.setPreferredSize(paneDimension);

    encryptedResponsePanel.add(encryptedResponseLabel);
    encryptedResponsePanel.add(encryptedResponseViewer.getComponent());
    encryptedResponsePanel.setPreferredSize(paneDimension);

    decryptedRequestPanel.add(decryptedRequestLabel);
    decryptedRequestPanel.add(decryptedRequestViewer.getComponent());
    decryptedRequestPanel.setPreferredSize(paneDimension);

    decryptedResponsePanel.add(decryptedResponseLabel);
    decryptedResponsePanel.add(decryptedResponseViewer.getComponent());
    decryptedResponsePanel.setPreferredSize(paneDimension);

    encryptedRequestResponseSplitPane.setLeftComponent(encryptedRequestPanel);
    encryptedRequestResponseSplitPane.setRightComponent(encryptedResponsePanel);
    encryptedRequestResponseSplitPane.setResizeWeight(0.5);
    viewSplitPane.addTab("Encrypted", encryptedRequestResponseSplitPane);

    decryptedRequestResponseSplitPane.setLeftComponent(decryptedRequestPanel);
    decryptedRequestResponseSplitPane.setRightComponent(decryptedResponsePanel);
    decryptedRequestResponseSplitPane.setResizeWeight(0.5);
    viewSplitPane.addTab("Decrypted", decryptedRequestResponseSplitPane);

    actionSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

    actionSplitPane.setRightComponent(configurationPane);
    actionSplitPane.setLeftComponent(logTableScrollPane);

    actionSplitPane.setResizeWeight(0.5);

    mainSplitPane.setResizeWeight(0.5);
    mainSplitPane.setTopComponent(actionSplitPane);
    mainSplitPane.setBottomComponent(viewSplitPane);

    encryptedRequestResponseSplitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY,
        pce -> {
          decryptedRequestResponseSplitPane.setDividerLocation(
              encryptedRequestResponseSplitPane.getDividerLocation());
        });
    decryptedRequestResponseSplitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY,
        pce -> {
          encryptedRequestResponseSplitPane.setDividerLocation(
              decryptedRequestResponseSplitPane.getDividerLocation());
        });

    callbacks.customizeUiComponent(mainSplitPane);
    callbacks.customizeUiComponent(logTable);
    callbacks.customizeUiComponent(logTableScrollPane);
    callbacks.customizeUiComponent(viewSplitPane);
  }

  public CustomHttpHandler createHandlerWithScript(MontoyaApi api) {
    return new CustomHttpHandler(api, encryptionScript, decryptionScript,
        enableButton, tableModel, inScopeCheckBox, logManager);
  }

  private static JPanel createTabPanel(JTextArea script) {
    JPanel panel = new JPanel(new BorderLayout());

    script.setEditable(true);
    script.setLineWrap(true);
    script.setWrapStyleWord(true);
    script.setRows(30);
    script.setColumns(100);
    JScrollPane scriptScrollPane = new JScrollPane(script);

    panel.add(scriptScrollPane, BorderLayout.CENTER);

    return panel;
  }

  private static JPanel createSettingTabPanel(DefaultTableModel tableModel) {
    JPanel panel = new JPanel(new BorderLayout());

    JButton addFileButton = new JButton("Add File");
    addFileButton.setPreferredSize(buttonDimension);
    addFileButton.setMinimumSize(buttonDimension);
    addFileButton.setMaximumSize(buttonDimension);

    JButton removeSelectedButton = new JButton("Remove Selected");
    removeSelectedButton.setPreferredSize(buttonDimension);
    removeSelectedButton.setMinimumSize(buttonDimension);
    removeSelectedButton.setMaximumSize(buttonDimension);

    JButton clearAllButton = new JButton("Clear All");
    clearAllButton.setPreferredSize(buttonDimension);
    clearAllButton.setMinimumSize(buttonDimension);
    clearAllButton.setMaximumSize(buttonDimension);

    JTable table = new JTable(tableModel);
    JScrollPane scrollTable = new JScrollPane(table);

    JPanel buttonPanel = new JPanel();
    buttonPanel.setLayout(new GridBagLayout());

    buttonPanel.setPreferredSize(new Dimension(130, TEXT_HEIGHT * 9));

    GridBagConstraints c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_END;
    c.gridx = 0;
    c.weightx = 1;

    buttonPanel.add(addFileButton, c);
    buttonPanel.add(removeSelectedButton, c);
    buttonPanel.add(clearAllButton, c);

    addFileButton.addActionListener(new ActionListener() {

      @Override
      public void actionPerformed(ActionEvent e) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setCurrentDirectory(new File("D:\\Download\\node_modules"));
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

        int choice = fileChooser.showOpenDialog(panel);
        if (choice == JFileChooser.APPROVE_OPTION) {
          File selectedFile = fileChooser.getSelectedFile();
          if (selectedFile != null) {
            String filePath = selectedFile.getAbsolutePath();
            tableModel.addRow(new String[] { filePath });
          }
        }
      }
    });

    removeSelectedButton.addActionListener(new ActionListener() {
      @Override
      public void actionPerformed(ActionEvent e) {
        int selectedRow = table.getSelectedRow();
        if (selectedRow != -1) {
          tableModel.removeRow(selectedRow);
        }
      }
    });

    clearAllButton.addActionListener(new ActionListener() {
      @Override
      public void actionPerformed(ActionEvent e) {
        tableModel.setRowCount(0);
      }
    });

    panel.add(scrollTable, BorderLayout.CENTER);
    panel.add(buttonPanel, BorderLayout.EAST);

    return panel;
  }

  public static IBurpExtenderCallbacks getCallbacks() {
    return callbacks;
  }

  private void updateEncryptedRequestResponseViewer() {
    SwingUtilities.invokeLater(() -> {
      if (encryptedRequest != null) {
        encryptedRequestViewer.setMessage(encryptedRequest, true);
      } else {
        encryptedRequestViewer.setMessage(new byte[0], true);
      }

      if (encryptedResponse != null) {
        encryptedResponseViewer.setMessage(encryptedResponse, false);
      } else {
        encryptedResponseViewer.setMessage(new byte[0], false);
      }
    });
  }

  private void updateDecryptedRequestResponseViewer() {
    SwingUtilities.invokeLater(() -> {
      if (decryptedRequest != null) {
        decryptedRequestViewer.setMessage(decryptedRequest, true);
      } else {
        decryptedRequestViewer.setMessage(new byte[0], true);
      }

      if (decryptedResponse != null) {
        decryptedResponseViewer.setMessage(decryptedResponse, false);
      } else {
        decryptedResponseViewer.setMessage(new byte[0], false);
      }
    });
  }

  @Override
  public byte[] getRequest() {
    switch (viewSplitPane.getSelectedIndex()) {
      case 0:
        return currentEncryptedRequest.toByteArray().getBytes();
      case 1:
        return currentDecryptedRequest.toByteArray().getBytes();
      default:
        return currentEncryptedRequest.toByteArray().getBytes();
    }
  }

  @Override
  public byte[] getResponse() {
    switch (viewSplitPane.getSelectedIndex()) {
      case 0:
        return currentEncryptedResponse.toByteArray().getBytes();
      case 1:
        return currentDecryptedResponse.toByteArray().getBytes();
      default:
        return currentEncryptedResponse.toByteArray().getBytes();
    }
  }

  @Override
  public IHttpService getHttpService() {
    switch (viewSplitPane.getSelectedIndex()) {
      case 0:
        return null;
      case 1:
        return null;
      default:
        return null;
    }
  }

  public LogTableModel getLogTableModel() {
    return logManager.getLogTableModel();
  }

  public class LogTable extends JTable {

    private static final long serialVersionUID = 1L;

    public LogTable(TableModel tableModel) {
      super(tableModel);
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {
      super.changeSelection(row, col, toggle, extend);
      LogEntry logEntry = logManager.getLogEntry(convertRowIndexToModel(row));

      new Thread(() -> {
        encryptedRequest = logEntry.getEncryptedHttpRequest().toByteArray().getBytes();
        encryptedResponse = logEntry.getEncryptedHttpResponse().toByteArray().getBytes();
        decryptedRequest = logEntry.getDecryptedHttpRequest().toByteArray().getBytes();
        decryptedResponse = logEntry.getDecryptedHttpResponse().toByteArray().getBytes();

        currentEncryptedRequest = logEntry.getEncryptedHttpRequest();
        currentEncryptedResponse = logEntry.getEncryptedHttpResponse();
        currentDecryptedRequest = logEntry.getDecryptedHttpRequest();
        currentDecryptedResponse = logEntry.getDecryptedHttpResponse();

        updateEncryptedRequestResponseViewer();
        updateDecryptedRequestResponseViewer();

      }).start();

    }
  }
}