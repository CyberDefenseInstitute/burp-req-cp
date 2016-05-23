package cdi;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import burp.IParameter;
import burp.IRequestInfo;

public class EncodeUitls {

	public static String empty = "";
	public static String NEWLINE = System.getProperty("line.separator");

	private static List<Charset> decodeCharsets;

	static {
		decodeCharsets = new ArrayList<Charset>();
		decodeCharsets.add(Charset.forName("UTF-8"));
		decodeCharsets.add(Charset.forName("windows-31j"));
		decodeCharsets.add(Charset.forName("ISO-2022-JP"));
		decodeCharsets.add(Charset.forName("EUC-JP"));
	}

	public static String getParamValue(IParameter parameter, byte[] rawRequest, IRequestInfo requestInfo) {
		String valueString;
		if ((0 > parameter.getValueStart()) || (0 > parameter.getValueEnd())) {
			valueString = parameter.getValue();
		} else {
			byte[] rawValue = Arrays.copyOfRange(rawRequest, parameter.getValueStart(), parameter.getValueEnd());
			valueString = getFixedEncodeString(rawValue);
		}

		if (requestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED
				|| (requestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_NONE)) {

			try {
				valueString = URLDecoder.decode(valueString, "iso8859-1");
				valueString = getFixedEncodeString(valueString);
			} catch (Exception e) {
				e.printStackTrace();
				;
			}

		}

		return valueString;
	}

	public static String tryDecode(byte[] dat) {

		for (Charset charset : decodeCharsets) {
			CharsetDecoder decoder = charset.newDecoder();
			try {
				return decoder.decode(ByteBuffer.wrap(dat)).toString();
			} catch (CharacterCodingException e) {
				continue;
			}
		}
		return new String(dat);
	}

	public static String getFixedEncodeString(byte[] dat) {
		return tryDecode(dat);
	}

	public static String getFixedEncodeString(String s) {
		byte[] b;
		try {
			b = s.getBytes("iso8859-1");
		} catch (UnsupportedEncodingException e) {
			b = s.getBytes();
		}
		return getFixedEncodeString(b);
	}

	public static String truncate(String src, int max) {
		if (src == null) {
			return empty;
		}

		return (src.length() <= max) ? src : src.substring(0, max) + " (...)";
	}

	public static boolean isNullOrEmpty(String string) {
		if (null == string) {
			return true;
		}
		return empty.equals(string);
	}

	public static String getNotNullString(String string) {
		return (null == string) ? empty : string;
	}
}
