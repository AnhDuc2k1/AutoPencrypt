package extension.Logs;

import javax.swing.SwingUtilities;

public class LogManager {

  private LogTableModel logTableModel;

  public LogManager() {
    logTableModel = new LogTableModel();
  }

  public synchronized int getRowCount() {
    return logTableModel.getRowCount();
  }

  public synchronized LogTableModel getLogTableModel() {
    return logTableModel;
  }

  public synchronized void addEntry(LogEntry logEntry) {
    SwingUtilities.invokeLater(() -> {
      logTableModel.addLogEntry(logEntry);
    });
  }

  public synchronized LogEntry getLogEntry(int row) {
    return logTableModel.getLogEntry(row);
  }

  public synchronized void clearLog() {
    SwingUtilities.invokeLater(() -> {
      logTableModel.clearLogs();
    });
  }
}
