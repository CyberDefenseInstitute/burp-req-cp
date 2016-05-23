package cdi;

import java.awt.datatransfer.Clipboard;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.Toolkit;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;

public class MenuItem implements MouseListener {
	static final private String Separator = "\t";

	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private IHttpRequestResponse[] requestResponses;

	public MenuItem(IBurpExtenderCallbacks callbacks, IHttpRequestResponse[] requestResponses) {
		this.callbacks = callbacks;
		this.helpers = this.callbacks.getHelpers();
		this.requestResponses = requestResponses;
	}

	private String parseRequest(IHttpRequestResponse requestResponse) {
		StringBuilder requestStr = new StringBuilder();
		IRequestInfo requestInfo = this.helpers.analyzeRequest(requestResponse);
		byte[] rawRequest = requestResponse.getRequest();
		List<IParameter> parameters = requestInfo.getParameters();

		requestStr.append(getMethod(requestInfo, parameters, rawRequest));
		if (requestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_MULTIPART) {
			requestStr.append("(multipart)");
		}

		URL url = requestInfo.getUrl();
		requestStr.append(Separator);
		requestStr.append(url.getProtocol()).append("://").append(url.getHost());
		requestStr.append(Separator);
		requestStr.append(url.getPath());
		requestStr.append(Separator);

		boolean isFirstParam = true;
		for (IParameter parameter : parameters) {
			if (parameter.getType() == IParameter.PARAM_COOKIE) {
				continue;
			}

			if (isFirstParam) {
				isFirstParam = false;
			} else {
				requestStr.append("&");
			}

			String name = getParamName(parameter, rawRequest);
			requestStr.append(name).append("=");
			if ((parameter.getValueEnd() - parameter.getValueStart()) > 2048) {
				requestStr.append("(...too large...)");
				continue;
			}

			String valueString;
			if ((0 > parameter.getValueStart()) || (0 > parameter.getValueEnd())) {
				valueString = parameter.getValue();
			} else {
				byte[] rawValue = Arrays.copyOfRange(rawRequest, parameter.getValueStart(), parameter.getValueEnd());
				valueString = EncodeUitls.getFixedEncodeString(rawValue);
			}
			if (requestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_MULTIPART) {
				valueString = valueString.replaceAll("[\\x00-\\x1F\\x7F-\\xFF]", "");
			}

			requestStr.append(valueString);
		}

		return requestStr.toString();
	}

	private void requestCopy() {
		StringBuilder requestStr = new StringBuilder();
		for (IHttpRequestResponse requestResponse : this.requestResponses) {
			requestStr.append(parseRequest(requestResponse));
			requestStr.append(EncodeUitls.NEWLINE);
		}

		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		StringTransfer selection = new StringTransfer(requestStr.toString());
		clipboard.setContents(selection, null);

	}

	private static String getParamName(IParameter parameter, byte[] rawRequest) {
		String name;
		if ((0 > parameter.getNameStart()) || (0 > parameter.getNameEnd())) {
			name = EncodeUitls.getFixedEncodeString(parameter.getName());
		} else {
			byte[] rawName = Arrays.copyOfRange(rawRequest, parameter.getNameStart(), parameter.getNameEnd());
			name = EncodeUitls.getFixedEncodeString(rawName);
		}

		return name;
	}

	private static String getMethod(IRequestInfo requestInfo, List<IParameter> parameters, byte[] rawRequest) {
		String method = requestInfo.getMethod();

		if (method.equals("POST")) {
			for (IParameter parameter : parameters) {
				if (parameter.getType() != IParameter.PARAM_BODY) {
					continue;
				}

				if (getParamName(parameter, rawRequest).equals("_method")) {
					return parameter.getValue().toUpperCase() + "(POST)";
				}
			}
		}

		return method;
	}

	public void mouseClicked(MouseEvent ev) {
	}

	public void mouseEntered(MouseEvent ev) {
	}

	public void mouseExited(MouseEvent ev) {
	}

	public void mousePressed(MouseEvent ev) {
	}

	public void mouseReleased(MouseEvent ev) {
		requestCopy();
	}
}