package extension.Logs;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;

public class LogTableModel extends AbstractTableModel {

  private final ArrayList<LogEntry> log;

  public LogTableModel() {
    log = new ArrayList<>();
  }

  public void addLogEntry(LogEntry logEntry) {
    log.add(logEntry);
    fireTableDataChanged();
  }

  public void clearLogs() {
    log.clear();
    fireTableDataChanged();
  }

  public LogEntry getLogEntry(int row) {
    return log.get(row);
  }

  public ArrayList<LogEntry> getLog() {
    return log;
  }

  public int getLogCount() {
    return log.size();
  }

  @Override
  public int getRowCount() {
    return log.size();
  }

  @Override
  public int getColumnCount() {
    return 6;
  }

  @Override
  public String getColumnName(int columnIndex) {
    switch (columnIndex) {
      case 0:
        return "#";
      case 1:
        return "Method";
      case 2:
        return "URL";
      case 3:
        return "Status";
      case 4:
        return "Encrypted Length";
      case 5:
        return "Decrypted Length";
      default:
        return "";
    }
  }

  @Override
  public Class<?> getColumnClass(int columnIndex) {
    switch (columnIndex) {
      case 0:
        return Long.class;
      case 1:
        return String.class;
      case 2:
        return String.class;
      case 3:
        return Integer.class;
      case 4:
        return Integer.class;
      case 5:
        return Integer.class;
      default:
        return null;
    }
  }

  @Override
  public Object getValueAt(int rowIndex, int columnIndex) {
    LogEntry logEntry = log.get(rowIndex);
    switch (columnIndex) {
      case 0:
        return logEntry.getRequestResponseId();
      case 1:
        return logEntry.getModifiedMethod();
      case 2:
        return logEntry.getModifiedURL().toString();
      case 3:
        return logEntry.getOriginalResponseStatus();
      case 4:
        return logEntry.getOriginalLength();
      case 5:
        return logEntry.getModifiedLength();
      default:
        return "";
    }
  }
}
