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

public class BurpExtender implements IBurpExtender, BurpExtension, IMessageEditorController {

  private static IBurpExtenderCallbacks callbacks;
  private MontoyaApi montoyaApi;

  public static final int TEXT_HEIGHT = new JTextField().getPreferredSize().height;
  public static final Dimension buttonDimension = new Dimension(130, TEXT_HEIGHT);
  public static final Dimension configurationPaneDimension = new Dimension(600, 300);

  private static JSplitPane mainTabbedPane;
  private JTabbedPane tabs;

  private JSplitPane mainSplitPane;
  private JSplitPane userInterfaceSplitPane;

  private JPanel configurationPane;
  private JTabbedPane configurationTabbedPane;

  private JTextArea encryptionScript = new JTextArea(30, 100);
  private JTextArea decryptionScript = new JTextArea(30, 100);
  private JToggleButton activatedButton = new JToggleButton("Enable Extension");
  private JButton clearLogButton = new JButton("Clear logs");
  private DefaultTableModel tableModel = new DefaultTableModel(new Object[] { "File Path" }, 0);
  private JCheckBox isScopePreButton = new JCheckBox("In Scope Request");

  private JSplitPane originalRequestResponseSplitPane;
  private JSplitPane modifiedRequestResponseSplitPane;

  private LogTable logTable;
  private static LogManager logManager;

  private IMessageEditor originalRequestViewer;
  private IMessageEditor originalResponseViewer;
  private IMessageEditor modifiedRequestViewer;
  private IMessageEditor modifiedResponseViewer;

  private JPanel originalRequestPanel;
  private JPanel originalResponsePanel;
  private JPanel modifiedRequestPanel;
  private JPanel modifiedResponsePanel;

  byte[] originalRequest;
  byte[] originalResponse;
  byte[] modifiedRequest;
  byte[] modifiedResponse;

  private JLabel originalRequestLabel;
  private JLabel originalResponseLabel;
  private JLabel modifiedRequestLabel;
  private JLabel modifiedResponseLabel;

  private HttpRequest currentOriginalRequest;
  private HttpResponse currentOriginalResponse;
  private HttpRequest currentModifiedRequest;
  private HttpResponse currentModifiedResponse;

  @Override
  public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

    BurpExtender.callbacks = callbacks;

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
  }

  private void createUI() {
    GridBagConstraints c;

    mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

    originalRequestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
    modifiedRequestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

    configurationTabbedPane = new JTabbedPane();

    activatedButton.addChangeListener(e -> {
      if (activatedButton.isSelected()) {
        activatedButton.setText("Disable Extension");
      } else {
        activatedButton.setText("Enable Extension");
      }
    });

    clearLogButton.addActionListener(e -> {
      logManager.clearLog();

      originalRequest = null;
      originalResponse = null;
      modifiedRequest = null;
      modifiedResponse = null;

      currentOriginalRequest = null;
      currentOriginalResponse = null;
      currentModifiedRequest = null;
      currentModifiedResponse = null;
    });
    Dimension activatedDimension = new Dimension(150, TEXT_HEIGHT);
    activatedButton.setPreferredSize(activatedDimension);
    activatedButton.setMaximumSize(activatedDimension);
    activatedButton.setMinimumSize(activatedDimension);

    Dimension clearLogDimension = new Dimension(150, TEXT_HEIGHT);
    clearLogButton.setPreferredSize(clearLogDimension);
    clearLogButton.setMaximumSize(clearLogDimension);
    clearLogButton.setMinimumSize(clearLogDimension);

    configurationPane = new JPanel();
    configurationPane.setLayout(new GridBagLayout());
    configurationPane.setMinimumSize(configurationPaneDimension);
    configurationPane.setPreferredSize(configurationPaneDimension);
    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.NORTHWEST;

    JPanel toggleButtonPanel = new JPanel();
    toggleButtonPanel.add(activatedButton);
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
    optionsTabPane.add(this.isScopePreButton);

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
    logTable.getColumnModel().getColumn(1).setPreferredWidth(20);
    logTable.getColumnModel().getColumn(2).setPreferredWidth(250);
    logTable.getColumnModel().getColumn(3).setPreferredWidth(20);
    logTable.getColumnModel().getColumn(4).setPreferredWidth(20);
    logTable.getColumnModel().getColumn(5).setPreferredWidth(20);

    JScrollPane logTableScrollPane = new JScrollPane(logTable);
    logTableScrollPane.setMinimumSize(configurationPaneDimension);
    logTableScrollPane.setPreferredSize(new Dimension(10000, 10));

    tabs = new JTabbedPane();
    tabs.setMinimumSize(new Dimension(10000, 300));
    tabs.addChangeListener(e -> {
      switch (tabs.getSelectedIndex()) {
        case 0:
          updateOriginalRequestResponseViewer();
          break;
        default:
          updateModifiedRequestResponseViewer();
          break;
      }
    });

    originalRequestViewer = callbacks.createMessageEditor(this, false);
    originalResponseViewer = callbacks.createMessageEditor(this, false);
    modifiedRequestViewer = callbacks.createMessageEditor(this, false);
    modifiedResponseViewer = callbacks.createMessageEditor(this, false);

    originalRequestLabel = new JLabel("Request");
    originalResponseLabel = new JLabel("Response");
    modifiedRequestLabel = new JLabel("Request");
    modifiedResponseLabel = new JLabel("Response");

    originalRequestLabel.setForeground(new Color(0xff6633));
    originalResponseLabel.setForeground(new Color(0xff6633));
    modifiedRequestLabel.setForeground(new Color(0xff6633));
    modifiedResponseLabel.setForeground(new Color(0xff6633));

    originalRequestLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
    originalResponseLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
    modifiedRequestLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
    modifiedResponseLabel.setFont(new Font("SansSerif", Font.BOLD, 14));

    originalRequestPanel = new JPanel();
    originalResponsePanel = new JPanel();

    modifiedRequestPanel = new JPanel();
    modifiedResponsePanel = new JPanel();

    originalRequestPanel.setLayout(new BoxLayout(originalRequestPanel, BoxLayout.PAGE_AXIS));
    originalResponsePanel.setLayout(new BoxLayout(originalResponsePanel, BoxLayout.PAGE_AXIS));

    modifiedRequestPanel.setLayout(new BoxLayout(modifiedRequestPanel, BoxLayout.PAGE_AXIS));
    modifiedResponsePanel.setLayout(new BoxLayout(modifiedResponsePanel, BoxLayout.PAGE_AXIS));

    originalRequestPanel.add(originalRequestLabel);
    originalRequestPanel.add(originalRequestViewer.getComponent());
    originalRequestPanel.setPreferredSize(new Dimension(100000, 100000));

    originalResponsePanel.add(originalResponseLabel);
    originalResponsePanel.add(originalResponseViewer.getComponent());
    originalResponsePanel.setPreferredSize(new Dimension(100000, 100000));

    modifiedRequestPanel.add(modifiedRequestLabel);
    modifiedRequestPanel.add(modifiedRequestViewer.getComponent());
    modifiedRequestPanel.setPreferredSize(new Dimension(100000, 100000));

    modifiedResponsePanel.add(modifiedResponseLabel);
    modifiedResponsePanel.add(modifiedResponseViewer.getComponent());
    modifiedResponsePanel.setPreferredSize(new Dimension(100000, 100000));

    originalRequestResponseSplitPane.setLeftComponent(originalRequestPanel);
    originalRequestResponseSplitPane.setRightComponent(originalResponsePanel);
    originalRequestResponseSplitPane.setResizeWeight(0.50);
    tabs.addTab("Encrypted", originalRequestResponseSplitPane);

    modifiedRequestResponseSplitPane.setLeftComponent(modifiedRequestPanel);
    modifiedRequestResponseSplitPane.setRightComponent(modifiedResponsePanel);
    modifiedRequestResponseSplitPane.setResizeWeight(0.5);
    tabs.addTab("Decrypted", modifiedRequestResponseSplitPane);

    mainSplitPane.setResizeWeight(.00000000000001);
    mainSplitPane.setBottomComponent(tabs);

    userInterfaceSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

    userInterfaceSplitPane.setRightComponent(configurationPane);
    userInterfaceSplitPane.setLeftComponent(logTableScrollPane);
    userInterfaceSplitPane.setResizeWeight(1.0);

    mainSplitPane.setTopComponent(userInterfaceSplitPane);

    originalRequestResponseSplitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY,
        pce -> {
          modifiedRequestResponseSplitPane.setDividerLocation(
              originalRequestResponseSplitPane.getDividerLocation());
        });
    modifiedRequestResponseSplitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY,
        pce -> {
          originalRequestResponseSplitPane.setDividerLocation(
              modifiedRequestResponseSplitPane.getDividerLocation());
        });

    callbacks.customizeUiComponent(mainSplitPane);
    callbacks.customizeUiComponent(logTable);
    callbacks.customizeUiComponent(logTableScrollPane);
    callbacks.customizeUiComponent(tabs);
  }

  public HttpHandlerWithScript createHandlerWithScript(MontoyaApi api) {
    return new HttpHandlerWithScript(api, encryptionScript, decryptionScript,
        activatedButton, tableModel, isScopePreButton, logManager);
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

  private void updateOriginalRequestResponseViewer() {
    SwingUtilities.invokeLater(() -> {
      if (originalRequest != null) {
        originalRequestViewer.setMessage(originalRequest, true);
      } else {
        originalRequestViewer.setMessage(new byte[0], true);
      }

      if (originalResponse != null) {
        originalResponseViewer.setMessage(originalResponse, false);
      } else {
        originalResponseViewer.setMessage(new byte[0], false);
      }
    });
  }

  private void updateModifiedRequestResponseViewer() {
    SwingUtilities.invokeLater(() -> {
      if (modifiedRequest != null) {
        modifiedRequestViewer.setMessage(modifiedRequest, true);
      } else {
        modifiedRequestViewer.setMessage(new byte[0], true);
      }

      if (modifiedResponse != null) {
        modifiedResponseViewer.setMessage(modifiedResponse, false);
      } else {
        modifiedResponseViewer.setMessage(new byte[0], false);
      }
    });
  }

  @Override
  public byte[] getRequest() {
    switch (tabs.getSelectedIndex()) {
      case 0:
        return currentOriginalRequest.toByteArray().getBytes();
      case 1:
        return currentModifiedRequest.toByteArray().getBytes();
      default:
        return currentOriginalRequest.toByteArray().getBytes();
    }
  }

  @Override
  public byte[] getResponse() {
    switch (tabs.getSelectedIndex()) {
      case 0:
        return currentOriginalResponse.toByteArray().getBytes();
      case 1:
        return currentModifiedResponse.toByteArray().getBytes();
      default:
        return currentOriginalResponse.toByteArray().getBytes();
    }
  }

  @Override
  public IHttpService getHttpService() {
    switch (tabs.getSelectedIndex()) {
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
        originalRequest = logEntry.getOriginalHttpRequest().toByteArray().getBytes();
        originalResponse = logEntry.getOriginalHttpResponse().toByteArray().getBytes();
        modifiedRequest = logEntry.getModifiedHttpRequest().toByteArray().getBytes();
        modifiedResponse = logEntry.getModifiedHttpResponse().toByteArray().getBytes();

        currentOriginalRequest = logEntry.getOriginalHttpRequest();
        currentOriginalResponse = logEntry.getOriginalHttpResponse();
        currentModifiedRequest = logEntry.getModifiedHttpRequest();
        currentModifiedResponse = logEntry.getModifiedHttpResponse();

        updateOriginalRequestResponseViewer();
        updateModifiedRequestResponseViewer();
      }).start();

    }
  }
}