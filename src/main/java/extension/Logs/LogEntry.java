package extension.Logs;

import java.net.MalformedURLException;
import java.net.URL;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class LogEntry {

  private long requestId;
  private URL requestURL;
  private String requestMethod;
  private int requestStatus;

  private HttpRequest encryptedHttpRequest;
  private HttpResponse encryptedHttpResponse;

  private HttpRequest decryptedHttpRequest;
  private HttpResponse decryptedHttpResponse;

  private int encryptedLength;
  private int decryptedLength;

  public LogEntry(long requestId,
      HttpRequest encryptedHttpRequest, HttpResponse encryptedHttpResponse,
      HttpRequest decryptedHttpRequest, HttpResponse decryptedHttpResponse) throws MalformedURLException {

    this.requestId = requestId;
    this.requestURL = new URL(encryptedHttpRequest.url());
    this.requestMethod = encryptedHttpRequest.method();
    this.requestStatus = encryptedHttpResponse.statusCode();

    this.encryptedHttpRequest = encryptedHttpRequest;
    this.encryptedHttpResponse = encryptedHttpResponse;
    this.encryptedLength = encryptedHttpResponse.body().length();

    this.decryptedHttpRequest = decryptedHttpRequest;
    this.decryptedHttpResponse = decryptedHttpResponse;
    this.decryptedLength = decryptedHttpResponse.body().length();
  }

  public long getRequestId() {
    return requestId;
  }

  public void setRequestId(long requestId) {
    this.requestId = requestId;
  }

  public URL getRequestURL() {
    return requestURL;
  }

  public void setRequestURL(URL requestURL) {
    this.requestURL = requestURL;
  }

  public HttpRequest getEncryptedHttpRequest() {
    return encryptedHttpRequest;
  }

  public void setEncryptedHttpRequest(HttpRequest encryptedHttpRequest) {
    this.encryptedHttpRequest = encryptedHttpRequest;
  }

  public HttpResponse getEncryptedHttpResponse() {
    return encryptedHttpResponse;
  }

  public void setEncryptedHttpResponse(HttpResponse encryptedHttpResponse) {
    this.encryptedHttpResponse = encryptedHttpResponse;
  }

  public HttpRequest getDecryptedHttpRequest() {
    return decryptedHttpRequest;
  }

  public void setDecryptedHttpRequest(HttpRequest decryptedHttpRequest) {
    this.decryptedHttpRequest = decryptedHttpRequest;
  }

  public HttpResponse getDecryptedHttpResponse() {
    return decryptedHttpResponse;
  }

  public void setDecryptedHttpResponse(HttpResponse decryptedHttpResponse) {
    this.decryptedHttpResponse = decryptedHttpResponse;
  }

  public String getRequestMethod() {
    return requestMethod;
  }

  public void setRequestMethod(String requestMethod) {
    this.requestMethod = requestMethod;
  }

  public int getEncryptedLength() {
    return encryptedLength;
  }

  public void setEncryptedLength(int encryptedLength) {
    this.encryptedLength = encryptedLength;
  }

  public int getDecryptedLength() {
    return decryptedLength;
  }

  public void setDecryptedLength(int decryptedLength) {
    this.decryptedLength = decryptedLength;
  }

  public int getRequestStatus() {
    return requestStatus;
  }

  public void setRequestStatus(int requestStatus) {
    this.requestStatus = requestStatus;
  }
}