package extension.Logs;

import java.net.MalformedURLException;
import java.net.URL;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class LogEntry {

  private long requestResponseId;

  private HttpRequest originalHttpRequest;
  private HttpResponse originalHttpResponse;

  private HttpRequest modifiedHttpRequest;
  private HttpResponse modifiedHttpResponse;

  private URL originalURL;
  private URL modifiedURL;

  private String originalMethod;
  private String modifiedMethod;

  private int originalLength;
  private int modifiedLength;
  private int lengthDifference;
  private double responseDistance;

  private int originalResponseStatus;
  private int modifiedResponseStatus;

  private int originalRequestHashCode;
  private int modifiedRequestHashCode;

  public LogEntry(long requestResponseId,
      HttpRequest originalHttpRequest, HttpResponse originalHttpResponse,
      HttpRequest modifiedHttpRequest, HttpResponse modifiedHttpResponse) throws MalformedURLException {

    this.requestResponseId = requestResponseId;

    this.originalHttpRequest = originalHttpRequest;
    this.originalURL = new URL(originalHttpRequest.url());
    this.originalMethod = originalHttpRequest.method();

    this.originalHttpResponse = originalHttpResponse;
    this.originalResponseStatus = originalHttpResponse.statusCode();
    this.originalLength = originalHttpResponse.body().length();

    this.modifiedHttpRequest = modifiedHttpRequest;
    this.modifiedURL = new URL(modifiedHttpRequest.url());
    this.modifiedMethod = modifiedHttpRequest.method();

    this.modifiedHttpResponse = modifiedHttpResponse;
    this.modifiedResponseStatus = modifiedHttpResponse.statusCode();
    this.modifiedLength = modifiedHttpResponse.body().length();
  }

  public long getRequestResponseId() {
    return requestResponseId;
  }

  public void setRequestResponseId(long requestResponseId) {
    this.requestResponseId = requestResponseId;
  }

  public URL getOriginalURL() {
    return originalURL;
  }

  public HttpRequest getOriginalHttpRequest() {
    return originalHttpRequest;
  }

  public void setOriginalHttpRequest(HttpRequest originalHttpRequest) {
    this.originalHttpRequest = originalHttpRequest;
  }

  public HttpResponse getOriginalHttpResponse() {
    return originalHttpResponse;
  }

  public void setOriginalHttpResponse(HttpResponse originalHttpResponse) {
    this.originalHttpResponse = originalHttpResponse;
  }

  public HttpRequest getModifiedHttpRequest() {
    return modifiedHttpRequest;
  }

  public void setModifiedHttpRequest(HttpRequest modifiedHttpRequest) {
    this.modifiedHttpRequest = modifiedHttpRequest;
  }

  public HttpResponse getModifiedHttpResponse() {
    return modifiedHttpResponse;
  }

  public void setModifiedHttpResponse(HttpResponse modifiedHttpResponse) {
    this.modifiedHttpResponse = modifiedHttpResponse;
  }

  public void setOriginalURL(URL originalURL) {
    this.originalURL = originalURL;
  }

  public URL getModifiedURL() {
    return modifiedURL;
  }

  public void setModifiedURL(URL modifiedURL) {
    this.modifiedURL = modifiedURL;
  }

  public int getOriginalRequestHashCode() {
    return originalRequestHashCode;
  }

  public int getModifiedRequestHashCode() {
    return modifiedRequestHashCode;
  }

  public String getOriginalMethod() {
    return originalMethod;
  }

  public void setOriginalMethod(String originalMethod) {
    this.originalMethod = originalMethod;
  }

  public String getModifiedMethod() {
    return modifiedMethod;
  }

  public void setModifiedMethod(String modifiedMethod) {
    this.modifiedMethod = modifiedMethod;
  }

  public int getOriginalLength() {
    return originalLength;
  }

  public void setOriginalLength(int originalLength) {
    this.originalLength = originalLength;
  }

  public int getModifiedLength() {
    return modifiedLength;
  }

  public void setModifiedLength(int modifiedLength) {
    this.modifiedLength = modifiedLength;
  }

  public int getLengthDifference() {
    return lengthDifference;
  }

  public void setLengthDifference(int lengthDifference) {
    this.lengthDifference = lengthDifference;
  }

  public double getResponseDistance() {
    return responseDistance;
  }

  public void setResponseDistance(double responseDistance) {
    this.responseDistance = responseDistance;
  }

  public int getOriginalResponseStatus() {
    return originalResponseStatus;
  }

  public void setOriginalResponseStatus(int originalResponseStatus) {
    this.originalResponseStatus = originalResponseStatus;
  }

  public int getModifiedResponseStatus() {
    return modifiedResponseStatus;
  }

  public void setModifiedResponseStatus(int modifiedResponseStatus) {
    this.modifiedResponseStatus = modifiedResponseStatus;
  }

  public void setOriginalRequestHashCode(int originalRequestHashCode) {
    this.originalRequestHashCode = originalRequestHashCode;
  }

  public void setModifiedRequestHashCode(int modifiedRequestHashCode) {
    this.modifiedRequestHashCode = modifiedRequestHashCode;
  }
}